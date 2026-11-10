"""Simulador de dispositivos de campo de um espaço comunitário.

Cada dispositivo roda em uma thread com o PRÓPRIO cliente MQTT e o PRÓPRIO
certificado X.509 (RT-04: nada de segredo compartilhado). Modelos físicos simples
geram leituras plausíveis; falhas podem ser injetadas via /control/faults.json
(usado nos testes de detecção, caos e IA).

Tópicos:  dev/<cn>/telemetry  dev/<cn>/state  dev/<cn>/event  (publica)
          dev/<cn>/cmd                                         (assina)
"""
from __future__ import annotations

import json
import logging
import os
import random
import ssl
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import paho.mqtt.client as mqtt

SITE = os.environ["SITE"]
BROKER = os.environ.get("BROKER_HOST", f"broker-{SITE}")
PORT = int(os.environ.get("BROKER_PORT", "8883"))
CERTS = Path(os.environ.get("CERTS_DIR", "/certs"))
PERIOD = float(os.environ.get("PERIOD_S", "5"))
FAULTS = Path(os.environ.get("FAULTS_FILE", "/control/faults.json"))
DEVICES = os.environ["DEVICES"].split()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
rnd = random.Random()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def faults() -> dict:
    try:
        return json.loads(FAULTS.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


class Physics:
    """Estado físico compartilhado do espaço (ex.: bomba enche o reservatório)."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.level = rnd.uniform(55, 75)    # % reservatório
        self.pump_on = False
        self.soc = rnd.uniform(60, 90)      # % bateria
        self.gen_on = False
        self.temp = 5.0                     # °C câmara fria
        self.flood_cm = 0.0

    def step(self, dt: float) -> None:
        with self.lock:
            hour = datetime.now().hour
            consumption = 0.08 if 7 <= hour <= 18 else 0.02
            self.level += (0.35 if self.pump_on else 0.0) * dt / 5 - consumption * dt / 5
            self.level = max(0.0, min(100.0, self.level))
            pv = max(0.0, 1.0 - abs(hour - 12) / 6)
            self.soc += (pv * 0.15 + (0.3 if self.gen_on else 0) - 0.1) * dt / 5
            self.soc = max(0.0, min(100.0, self.soc))
            # câmara fria tende a 5 °C
            self.temp += (5.0 - self.temp) * 0.1 + rnd.gauss(0, 0.08)


class Device(threading.Thread):
    kind = "generic"

    def __init__(self, cn: str, phys: Physics) -> None:
        super().__init__(daemon=True, name=cn)
        self.cn, self.phys, self.seq = cn, phys, 0
        self.log = logging.getLogger(cn)
        self.client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=cn, clean_session=False)
        d = CERTS / cn
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(d / "ca.pem"))
        ctx.load_cert_chain(str(d / "cert.pem"), str(d / "key.pem"))
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        self.client.tls_set_context(ctx)
        self.client.on_connect = self._on_connect
        self.client.on_message = self._on_message
        self.client.reconnect_delay_set(1, 30)

    # --- MQTT ---
    def _on_connect(self, c, _u, _f, rc, _p):
        self.log.info("conectado rc=%s", rc)
        c.subscribe(f"dev/{self.cn}/cmd", qos=1)

    def _on_message(self, _c, _u, msg):
        try:
            self.on_cmd(json.loads(msg.payload))
        except Exception as e:  # noqa: BLE001
            self.log.warning("comando inválido: %s", e)

    def pub(self, sub: str, data: dict, qos: int = 1, retain: bool = False) -> None:
        self.seq += 1
        body = {"device": self.cn, "type": self.kind, "site": SITE, "seq": self.seq, "ts": now(), **data}
        self.client.publish(f"dev/{self.cn}/{sub}", json.dumps(body), qos=qos, retain=retain)

    # --- comportamento ---
    def on_cmd(self, cmd: dict) -> None:
        self.log.info("comando ignorado: %s", cmd)

    def read(self) -> dict:
        return {}

    def run(self) -> None:
        self.client.connect_async(BROKER, PORT, keepalive=30)
        self.client.loop_start()
        while True:
            f = faults().get(self.cn, {})
            if f.get("offline"):
                time.sleep(PERIOD)
                continue
            data = self.read()
            for k, v in f.get("offset", {}).items():
                if k in data:
                    data[k] = round(data[k] + v, 2)
            self.pub("telemetry", data)
            time.sleep(PERIOD * rnd.uniform(0.9, 1.1))


class Level(Device):
    kind = "nivel-reservatorio"

    def read(self):
        return {"level_pct": round(self.phys.level + rnd.gauss(0, 0.3), 2)}


class Pump(Device):
    kind = "bomba"

    def on_cmd(self, cmd):
        action = cmd.get("action")
        if action in ("on", "off"):
            with self.phys.lock:
                self.phys.pump_on = action == "on"
            self.log.info("bomba -> %s (origem=%s)", action, cmd.get("origin"))
            self.pub("state", {"on": self.phys.pump_on, "cmd_id": cmd.get("id"), "origin": cmd.get("origin")},
                     retain=True)

    def read(self):
        return {"on": self.phys.pump_on, "current_a": round((4.2 if self.phys.pump_on else 0) + rnd.gauss(0, .05), 2)}


class Turbidity(Device):
    kind = "turbidez"

    def read(self):
        return {"ntu": round(abs(rnd.gauss(0.6, 0.15)), 2)}


class Chlorine(Device):
    kind = "cloro"

    def read(self):
        return {"mg_l": round(rnd.gauss(1.2, 0.08), 2)}


class ColdRoom(Device):
    kind = "camara-fria"

    def read(self):
        return {"temp_c": round(self.phys.temp, 2), "door_open": rnd.random() < 0.01}


class Energy(Device):
    kind = "energia"

    def read(self):
        hour = datetime.now().hour
        return {"soc_pct": round(self.phys.soc, 1),
                "pv_w": round(max(0, 1 - abs(hour - 12) / 6) * 1800 + rnd.gauss(0, 30), 1),
                "load_w": round(rnd.gauss(650, 60), 1),
                "grid": True}


class Generator(Device):
    kind = "gerador"

    def on_cmd(self, cmd):
        if cmd.get("action") in ("on", "off"):
            with self.phys.lock:
                self.phys.gen_on = cmd["action"] == "on"
            self.pub("state", {"on": self.phys.gen_on, "cmd_id": cmd.get("id"), "origin": cmd.get("origin")},
                     retain=True)

    def read(self):
        return {"on": self.phys.gen_on, "fuel_pct": round(rnd.uniform(70, 72), 1)}


class Flood(Device):
    kind = "alagamento"

    def read(self):
        return {"water_cm": round(max(0.0, rnd.gauss(0.2, 0.2)), 2)}


class SoilMoisture(Device):
    kind = "umidade-solo"

    def read(self):
        return {"vwc_pct": round(rnd.gauss(32, 2), 1)}


class AirQuality(Device):
    kind = "qualidade-ar"

    def read(self):
        return {"co2_ppm": round(rnd.gauss(650, 60)), "pm25_ugm3": round(abs(rnd.gauss(12, 4)), 1),
                "rh_pct": round(rnd.gauss(60, 5), 1)}


class Lock(Device):
    """Fechadura RFID/QR. Crachás sintéticos (Faker não é necessário: IDs aleatórios)."""
    kind = "fechadura"
    BADGES = [f"BADGE-{i:04d}" for i in range(1, 41)]

    def read(self):
        if rnd.random() < 0.15:
            ok = rnd.random() > 0.05
            self.pub("event", {"event": "access", "badge": rnd.choice(self.BADGES),
                               "granted": ok, "method": rnd.choice(["rfid", "qr"])})
        return {"locked": True, "battery_pct": round(rnd.uniform(80, 82), 1)}


KINDS = {c.kind: c for c in (Level, Pump, Turbidity, Chlorine, ColdRoom, Energy, Generator, Flood,
                             SoilMoisture, AirQuality, Lock)}


def main() -> None:
    phys = Physics()
    for name in DEVICES:
        cn = f"{SITE}-{name}"
        cls = KINDS.get(name)
        if cls is None:
            logging.warning("tipo desconhecido %s (usando genérico)", name)
            cls = Device
        cls(cn, phys).start()
    while True:
        phys.step(1.0)
        time.sleep(1.0)


if __name__ == "__main__":
    main()
