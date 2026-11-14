"""Camada de apresentação do painel (RT-21): transforma identificadores técnicos em texto legível.

Só afeta o que é EXIBIDO. Banco, logs, auditoria e valores de formulário continuam com os
identificadores originais (ex.: `escola-bomba`, `safe_mode`). Todo filtro devolve o valor original
quando não conhece a entrada, para nunca esconder dado inesperado (inclusive em investigação).
"""
from __future__ import annotations

import re
from datetime import datetime

ESPACOS = {"centro": "Centro comunitário", "escola": "Escola", "ubs": "UBS", "horta": "Horta", "abrigo": "Abrigo"}

EQUIPAMENTOS = {
    "nivel-reservatorio": "Nível do reservatório", "bomba": "Bomba d'água", "turbidez": "Turbidez da água",
    "cloro": "Cloro da água", "fechadura": "Fechadura", "camara-fria": "Câmara fria", "energia": "Energia",
    "gerador": "Gerador", "alagamento": "Sensor de alagamento", "umidade-solo": "Umidade do solo",
    "qualidade-ar": "Qualidade do ar",
}

# chave da telemetria -> (rótulo, unidade, casas decimais) | (rótulo, texto se verdadeiro, texto se falso)
LEITURAS = {
    "level_pct": ("Nível", "%", 1), "current_a": ("Corrente", "A", 2), "ntu": ("Turbidez", "NTU", 2),
    "mg_l": ("Cloro", "mg/L", 2), "temp_c": ("Temperatura", "°C", 1), "soc_pct": ("Bateria", "%", 0),
    "pv_w": ("Geração solar", "W", 0), "load_w": ("Consumo", "W", 0), "fuel_pct": ("Combustível", "%", 0),
    "water_cm": ("Água no piso", "cm", 1), "vwc_pct": ("Umidade do solo", "%", 1), "co2_ppm": ("CO₂", "ppm", 0),
    "pm25_ugm3": ("Partículas finas (PM2,5)", "µg/m³", 1), "rh_pct": ("Umidade do ar", "%", 0),
    "battery_pct": ("Bateria", "%", 0),
    "on": ("Estado", "ligado", "desligado"), "door_open": ("Porta", "aberta", "fechada"),
    "grid": ("Rede elétrica", "disponível", "em falta"), "locked": ("Tranca", "travada", "destravada"),
}
# grandezas que não existem abaixo de zero: ruído do sensor em torno de 0 é exibido como 0
SEM_NEGATIVO = {"pv_w", "current_a", "water_cm", "ntu"}
OCULTAS = {"device", "type", "site", "seq", "ts", "cmd_id", "origin"}

ACOES = {
    "on": "Ligar", "off": "Desligar", "safe_mode": "Modo seguro", "lock": "Travar",
    "unlock_all": "Liberar todas as portas", "set_schedule": "Alterar agenda", "isolate": "Isolar dispositivo",
    # respostas do SOAR
    "bloquear_conta": "Bloquear conta", "revogar_sessao_vpn": "Encerrar sessão da VPN",
    "bloquear_ip": "Bloquear endereço IP", "modo_seguro": "Colocar em modo seguro",
    "encerrar_todas_sessoes_vpn": "Encerrar todas as sessões da VPN",
    "revogar_certificado": "Revogar certificado", "isolar_dispositivo": "Isolar dispositivo",
    # trilha de auditoria
    "login": "Entrou no painel", "access_search": "Buscou no histórico de acessos",
    "alarm_ack": "Reconheceu alarme", "command_create": "Solicitou comando",
    "command_approve": "Aprovou comando", "command_deny": "Negou comando",
    "soc_action_aprovada": "Aprovou resposta do SOC", "soc_action_negada": "Negou resposta do SOC",
    "lock_account": "Bloqueou conta", "pump_schedule_update": "Alterou a agenda da bomba",
}

PERFIS = {"operador": "operador", "tecnico": "técnico", "coordenacao": "coordenação", "auditor": "auditor"}
METODOS = {"rfid": "crachá", "qr": "QR code"}
DETALHES = {"q": "busca", "site": "espaço", "dia": "dia", "rows": "resultados", "horas": "duração (h)",
            "action": "ação", "risk": "risco", "cmd_id": "comando",
            "new": "nova", "old": "anterior"}
UUID_RE = re.compile(r"\b([0-9a-f]{8})-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")


def numero(v, casas: int = 1) -> str:
    """Número no padrão brasileiro (vírgula decimal)."""
    t = f"{float(v):.{casas}f}"
    if float(t) == 0:
        t = t.lstrip("-")
    return t.replace(".", ",")


def espaco(s):
    return ESPACOS.get(s, s)


def equip(device, com_espaco: bool = False):
    """`escola-bomba` -> "Bomba d'água" (ou "Bomba d'água · Escola")."""
    site, _, tipo = str(device).partition("-")
    if site not in ESPACOS or tipo not in EQUIPAMENTOS:
        return device
    return f"{EQUIPAMENTOS[tipo]} · {ESPACOS[site]}" if com_espaco else EQUIPAMENTOS[tipo]


def leituras(data) -> list[tuple[str, str]]:
    """Dicionário de telemetria -> lista de (rótulo, valor com unidade)."""
    out = []
    for k, v in (data or {}).items():
        if k in OCULTAS:
            continue
        spec = LEITURAS.get(k)
        if spec and isinstance(v, bool):
            out.append((spec[0], spec[1] if v else spec[2]))
        elif spec and isinstance(v, (int, float)) and isinstance(spec[2], int):
            v = max(v, 0) if k in SEM_NEGATIVO else v
            out.append((spec[0], f"{numero(v, spec[2])} {spec[1]}"))
        else:
            out.append((k, str(v)))
    return out


def acao(a):
    return ACOES.get(a, str(a).replace("_", " "))


def perfil(p):
    return PERFIS.get(p, p)


def metodo(m):
    return METODOS.get(m, m)


def quem(s) -> tuple[str, str]:
    """`diego.op (db:va_painel_legado)` -> ("diego.op", "direto no banco, usuário va_painel_legado")."""
    m = re.fullmatch(r"(.*?) \(db:(.+)\)", str(s or ""))
    return (m.group(1), f"direto no banco, usuário {m.group(2)}") if m else (s, "")


def janelas(w) -> list[str]:
    """`05:00-07:00,17:00-19:00` -> ["05:00 às 07:00", "17:00 às 19:00"]."""
    partes = [p for p in str(w or "").split(",") if p]
    return [p.replace("-", " às ") if re.fullmatch(r"\d{2}:\d{2}-\d{2}:\d{2}", p) else p for p in partes]


def detalhes(d) -> list[tuple[str, str]]:
    """JSON da auditoria -> pares (rótulo, valor), sem campos vazios."""
    if not isinstance(d, dict):
        return [("detalhe", str(d))] if d else []
    out = []
    for k, v in d.items():
        if v in ("", None):
            continue
        v = ESPACOS.get(v, v) if k == "site" else ACOES.get(v, v) if k == "action" else v
        out.append((DETALHES.get(k, k), UUID_RE.sub(r"\1…", str(v))))
    return out


def limpo(texto):
    """Resultado do SOAR: tira a sintaxe de lista do Python e encurta identificadores longos."""
    t = re.sub(r"\[([^\[\]]*)\]", lambda m: m.group(1).replace("'", ""), str(texto or ""))
    return UUID_RE.sub(r"\1…", t)


def quando(ts, segundos: bool = False):
    """Data/hora curta. Aceita qualquer valor (devolve como veio se não for data)."""
    if not isinstance(ts, datetime):
        return ts
    return ts.strftime("%d/%m %H:%M:%S" if segundos else "%d/%m %H:%M")


def nivel(n) -> tuple[str, str]:
    """Nível do Wazuh (0-15) -> (texto, classe da etiqueta)."""
    try:
        n = int(n)
    except (TypeError, ValueError):
        return str(n), "neutral"
    return ("alto", "bad") if n >= 12 else ("médio", "warn") if n >= 7 else ("baixo", "neutral")


FILTROS = {"espaco": espaco, "equip": equip, "leituras": leituras, "acao": acao, "perfil": perfil,
           "metodo": metodo, "quem": quem, "janelas": janelas, "detalhes": detalhes, "limpo": limpo,
           "quando": quando, "nivel": nivel, "numero": numero}
