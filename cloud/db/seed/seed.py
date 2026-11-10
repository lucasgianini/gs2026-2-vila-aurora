"""Popula o banco com dados 100% SINTÉTICOS (RT-19) e cria operadores com MFA.

Credenciais geradas vão para /secrets/operadores.txt (fora do git).
Idempotente: não recria o que já existe.
"""
import hashlib
import hmac
import os
import secrets

import psycopg
import pyotp
from argon2 import PasswordHasher
from faker import Faker

fake = Faker("pt_BR")
Faker.seed(2026)   # reprodutível
KEY = os.environ["PSEUDO_KEY"].encode()
ph = PasswordHasher()

OPERADORES = [  # username, nome (fictício), perfil
    ("marta.coord", "Marta (coord. voluntários)", "coordenacao"),
    ("bruno.coord", "Bruno (coord. geral)", "coordenacao"),
    ("carla.tec", "Carla (técnica)", "tecnico"),
    ("diego.op", "Diego (operador)", "operador"),
    ("elisa.aud", "Elisa (auditora)", "auditor"),
]


def pseudo(badge: str) -> str:
    return "p_" + hmac.new(KEY, badge.encode(), hashlib.sha256).hexdigest()[:16]


with psycopg.connect(host="db", dbname="vilaaurora", user=os.environ["POSTGRES_USER"],
                     password=os.environ["POSTGRES_PASSWORD"]) as conn, conn.cursor() as cur:
    cur.execute("SELECT count(*) FROM cadastro.pessoas")
    if cur.fetchone()[0] == 0:
        papeis = ["voluntario"] * 20 + ["morador"] * 12 + ["tecnico"] * 3 + ["equipe_ubs"] * 5
        for i, papel in enumerate(papeis, start=1):
            nome = fake.name()
            cur.execute("INSERT INTO cadastro.pessoas(pseudonimo,nome,email,telefone,papel) VALUES (%s,%s,%s,%s,%s)",
                        (pseudo(f"BADGE-{i:04d}"), nome, fake.free_email(), fake.cellphone_number(), papel))
        print("pessoas sintéticas: 40")
    lines = []
    for user, nome, role in OPERADORES:
        cur.execute("SELECT 1 FROM cadastro.operadores WHERE username=%s", (user,))
        if cur.fetchone():
            continue
        pw = secrets.token_urlsafe(12)
        totp = pyotp.random_base32()
        cur.execute("INSERT INTO cadastro.operadores(username,nome,password_hash,totp_secret,role,telefone_verificacao)"
                    " VALUES (%s,%s,%s,%s,%s,%s)", (user, nome, ph.hash(pw), totp, role, fake.cellphone_number()))
        lines.append(f"{user}\t{role}\tsenha={pw}\ttotp={totp}\t"
                     f"{pyotp.TOTP(totp).provisioning_uri(user, issuer_name='Vila Aurora')}")
    for site in ("escola", "horta"):
        cur.execute("INSERT INTO ops.pump_schedule(site,windows,updated_by) VALUES (%s,%s,'seed') "
                    "ON CONFLICT DO NOTHING", (site, "05:00-07:00,17:00-19:00"))
    if lines:
        os.makedirs("/secrets", exist_ok=True)
        with open("/secrets/operadores.txt", "a") as f:
            f.write("\n".join(lines) + "\n")
        print(f"operadores criados: {len(lines)} (credenciais em secrets/operadores.txt)")
