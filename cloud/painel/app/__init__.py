"""Painel de supervisão da Rede Vila Aurora.

PAINEL_VARIANT=corrigido (padrão): MFA TOTP, RBAC, CSRF, consultas parametrizadas,
    validação no servidor, erros genéricos, cabeçalhos de segurança  (RT-08, RT-09, RT-21)
PAINEL_VARIANT=legado: reproduz o painel do INC-VA-0712 (senha apenas, SQLi) — só no laboratório.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timedelta, timezone
from functools import wraps

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError
from flask import (Flask, abort, flash, g, redirect, render_template, request, session, url_for)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from psycopg.types.json import Jsonb

from .db import VARIANT, query

LEGADO = VARIANT == "legado"
if LEGADO:
    from . import repo_legado as repo
else:
    from . import repo

ph = PasswordHasher()
LOG = open(os.environ.get("LOG_PATH", "/var/log/vilaaurora/painel.jsonl"), "a", buffering=1)

ROLES = ("operador", "tecnico", "coordenacao", "auditor")
# Permissões por perfil (RT-09). Auditor é somente leitura.
PERMS = {
    "ver_painel":      {"operador", "tecnico", "coordenacao", "auditor"},
    "reconhecer":      {"operador", "tecnico", "coordenacao"},
    "comandar":        {"tecnico", "coordenacao"},
    "aprovar":         {"coordenacao"},
    "agenda":          {"tecnico", "coordenacao"},
    "ver_acessos":     {"coordenacao", "auditor"},
    "ver_auditoria":   {"coordenacao", "auditor"},
    "ver_soc":         {"tecnico", "coordenacao", "auditor"},
}
# Ações de alto impacto exigem aprovação de outra pessoa (RT-15)
HIGH_IMPACT = {("bomba", "off"), ("gerador", "off"), ("fechadura", "unlock_all")}
ACTIONS = {"bomba": ("on", "off", "safe_mode"), "gerador": ("on", "off", "safe_mode"),
           "fechadura": ("lock", "unlock_all")}
WINDOWS_RE = re.compile(r"^(\d{2}:\d{2}-\d{2}:\d{2})(,\d{2}:\d{2}-\d{2}:\d{2}){0,5}$")


def client_ip() -> str:
    return request.headers.get("X-Real-IP") or request.remote_addr or "?"


def log(event: str, severity: str = "info", **kw) -> None:
    rec = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), "app": "va-painel",
           "variant": VARIANT, "event": event, "severity": severity, "src_ip": client_ip(),
           "user": session.get("user"), **kw}
    LOG.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")


def audit(action: str, target: str | None = None, **detail) -> None:
    query("INSERT INTO audit.log(actor, action, target, ip, detail) VALUES (%s,%s,%s,%s,%s)",
          (session.get("user", "anon"), action, target, client_ip(), Jsonb(detail)))


def create_app() -> Flask:
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=os.environ["FLASK_SECRET_KEY"],
        SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
        SESSION_COOKIE_NAME="__Host-va" if not LEGADO else "session",
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        WTF_CSRF_ENABLED=not LEGADO,
    )
    CSRFProtect(app)
    if LEGADO:   # legado não tinha limitação de tentativas
        rate_limit = lambda fn: fn  # noqa: E731
    else:
        limiter = Limiter(get_remote_address, app=app, storage_uri="memory://", default_limits=[])
        rate_limit = limiter.limit("10/minute", methods=["POST"])

    @app.context_processor
    def ctx():
        return {"variant": VARIANT, "user": session.get("user"), "role": session.get("role"),
                "can": lambda p: session.get("role") in PERMS.get(p, ())}

    @app.after_request
    def headers(resp):
        if not LEGADO:
            resp.headers.update({
                "Content-Security-Policy": "default-src 'self'; img-src 'self' data:; "
                                           "frame-ancestors 'none'; form-action 'self'; base-uri 'none'",
                "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
                "X-Frame-Options": "DENY", "Cache-Control": "no-store",
                "Strict-Transport-Security": "max-age=31536000"})
        return resp

    def login_required(perm: str = "ver_painel"):
        def deco(fn):
            @wraps(fn)
            def wrapper(*a, **kw):
                if not session.get("user") or (not LEGADO and not session.get("mfa_ok")):
                    return redirect(url_for("login", next=request.path))
                if not LEGADO and session.get("role") not in PERMS[perm]:
                    log("forbidden", "warning", perm=perm, path=request.path)
                    abort(403)
                return fn(*a, **kw)
            return wrapper
        return deco

    # ------------------------------------------------------------------ autenticação
    @app.route("/login", methods=["GET", "POST"])
    @rate_limit
    def login():
        if request.method == "GET":
            return render_template("login.html")
        username = request.form.get("username", "").strip().lower()[:32]
        password = request.form.get("password", "")
        u = query("SELECT id, username, nome, password_hash, totp_secret, role, ativo, falhas, bloqueado_ate "
                  "FROM cadastro.operadores WHERE username=%s", (username,), one=True)
        now = datetime.now(timezone.utc)
        if u and u["bloqueado_ate"] and u["bloqueado_ate"] > now and not LEGADO:
            log("login_locked", "warning", username=username)
            flash("Usuário ou senha incorretos.")       # mesma mensagem: não revela bloqueio
            return render_template("login.html"), 401
        ok = False
        if u and u["ativo"]:
            try:
                ok = ph.verify(u["password_hash"], password)
            except VerificationError:
                ok = False
        if not ok:
            if u and not LEGADO:
                falhas = u["falhas"] + 1
                query("UPDATE cadastro.operadores SET falhas=%s, bloqueado_ate=%s WHERE id=%s",
                      (falhas, now + timedelta(minutes=15) if falhas >= 5 else None, u["id"]))
            log("login_failure", "warning", username=username)
            flash("Usuário ou senha incorretos.")
            return render_template("login.html"), 401
        session.clear()
        session.update(user=u["username"], role=u["role"], nome=u["nome"], uid=u["id"])
        session.permanent = True
        if LEGADO:
            log("login_success", username=username, mfa=False)
            return redirect(url_for("index"))
        if not u["totp_secret"]:
            log("login_no_mfa_enrolled", "warning", username=username)
            session.clear()
            flash("MFA não cadastrado. Procure a coordenação.")
            return render_template("login.html"), 403
        session["mfa_pending"] = True
        return redirect(url_for("mfa"))

    @app.route("/login/mfa", methods=["GET", "POST"])
    @rate_limit
    def mfa():
        if LEGADO or not session.get("mfa_pending"):
            return redirect(url_for("login"))
        if request.method == "GET":
            return render_template("mfa.html")
        code = re.sub(r"\D", "", request.form.get("code", ""))[:6]
        u = query("SELECT id, totp_secret, falhas FROM cadastro.operadores WHERE id=%s",
                  (session["uid"],), one=True)
        if not u or not pyotp.TOTP(u["totp_secret"]).verify(code, valid_window=1):
            falhas = (u["falhas"] if u else 0) + 1
            if u:
                query("UPDATE cadastro.operadores SET falhas=%s, bloqueado_ate=%s WHERE id=%s",
                      (falhas, datetime.now(timezone.utc) + timedelta(minutes=15) if falhas >= 5 else None,
                       u["id"]))
            log("mfa_failure", "warning", username=session.get("user"))
            flash("Código inválido.")
            return render_template("mfa.html"), 401
        query("UPDATE cadastro.operadores SET falhas=0, bloqueado_ate=NULL WHERE id=%s", (u["id"],))
        session.pop("mfa_pending")
        session["mfa_ok"] = True
        log("login_success", username=session["user"], mfa=True)
        audit("login", session["user"])
        return redirect(url_for("index"))

    @app.post("/logout")
    def logout():
        log("logout")
        session.clear()
        return redirect(url_for("login"))

    # ------------------------------------------------------------------ visão geral
    @app.get("/")
    @login_required()
    def index():
        leituras = query("SELECT device, edge, ts, data FROM ops.ultima_leitura ORDER BY device")
        alarmes = query("SELECT id, site, alarm, severity, message, raised_at, ack_by FROM ops.alarms "
                        "WHERE cleared_at IS NULL ORDER BY raised_at DESC")
        por_site: dict[str, list] = {}
        for r in leituras:
            por_site.setdefault(r["edge"].removeprefix("edge-"), []).append(r)
        agora = datetime.now(timezone.utc)
        return render_template("index.html", por_site=por_site, alarmes=alarmes, agora=agora)

    @app.post("/alarmes/<int:aid>/reconhecer")
    @login_required("reconhecer")
    def reconhecer(aid):
        query("UPDATE ops.alarms SET ack_by=%s, ack_at=now() WHERE id=%s AND ack_by IS NULL",
              (session["user"], aid))
        audit("alarm_ack", str(aid))
        log("alarm_ack", alarm_id=aid)
        return redirect(url_for("index"))

    # ------------------------------------------------------------------ histórico de acessos (alvo do SQLi)
    @app.get("/acessos")
    @login_required("ver_acessos")
    def acessos():
        term, site, dia = request.args.get("q", ""), request.args.get("site", ""), request.args.get("dia", "")
        rows, erro = [], None
        if request.args:
            try:
                t, s, d = repo.validate_search(term, site, dia)
                rows = repo.search_acessos(t, s, d)
                log("access_search", q=term, site=site, dia=dia, rows=len(rows))
            except repo.InvalidInput as e:
                log("input_rejected", "warning", field="q", q=term, site=site, dia=dia, reason=str(e))
                erro = str(e)
            except Exception as e:  # noqa: BLE001
                log("sql_error", "high", q=term, error=str(e)[:500])
                # legado devolve o erro do banco (vazamento de detalhes); corrigido: genérico
                erro = f"Erro: {e}" if LEGADO else "Não foi possível concluir a busca."
        if not LEGADO and request.args:
            audit("access_search", None, q=term, site=site, dia=dia, rows=len(rows))
        return render_template("acessos.html", rows=rows, erro=erro, q=term, site=site, dia=dia,
                               sites=repo_sites())

    # ------------------------------------------------------------------ comandos (RT-15)
    @app.route("/comandos", methods=["GET", "POST"])
    @login_required("comandar" if not LEGADO else "ver_painel")
    def comandos():
        if request.method == "POST":
            device = request.form.get("device", "")
            action = request.form.get("action", "")
            m = re.fullmatch(r"(centro|escola|ubs|horta|abrigo)-(bomba|gerador|fechadura)", device)
            if not m or action not in ACTIONS.get(m.group(2), ()):
                log("input_rejected", "warning", field="command", device=device, action=action)
                flash("Dispositivo ou ação inválidos.")
                return redirect(url_for("comandos"))
            alto = (m.group(2), action) in HIGH_IMPACT
            st = "aguardando_aprovacao" if alto else "pendente"
            row = query("INSERT INTO ops.commands(edge, device, action, risk, requested_by, status) "
                        "VALUES (%s,%s,%s,%s,%s,%s) RETURNING id",
                        (f"edge-{m.group(1)}", device, action, "alto" if alto else "baixo", session["user"], st),
                        one=True)
            audit("command_create", device, action=action, risk="alto" if alto else "baixo", cmd_id=str(row["id"]))
            log("command_created", "notice", device=device, action=action, risk="alto" if alto else "baixo",
                cmd_id=str(row["id"]), hour=datetime.now().hour)
            flash("Ação de alto impacto: aguardando aprovação da coordenação." if alto else "Comando enviado.")
            return redirect(url_for("comandos"))
        cmds = query("SELECT id, edge, device, action, risk, requested_by, approved_by, status, created_at, "
                     "result FROM ops.commands ORDER BY created_at DESC LIMIT 50")
        devs = [f"{s}-{d}" for s in repo_sites() for d in ("bomba", "gerador", "fechadura")]
        return render_template("comandos.html", cmds=cmds, devs=devs, actions=ACTIONS)

    @app.post("/comandos/<uuid:cid>/aprovar")
    @login_required("aprovar")
    def aprovar(cid):
        decisao = request.form.get("decisao")
        c = query("SELECT requested_by, status FROM ops.commands WHERE id=%s", (str(cid),), one=True)
        if not c or c["status"] != "aguardando_aprovacao":
            abort(404)
        if c["requested_by"] == session["user"]:
            flash("Quem solicitou não pode aprovar (quatro olhos).")
            return redirect(url_for("comandos"))
        if decisao == "aprovar":
            query("UPDATE ops.commands SET approved_by=%s, status='pendente' WHERE id=%s",
                  (session["user"], str(cid)))
        else:
            query("UPDATE ops.commands SET status='cancelado' WHERE id=%s", (str(cid),))
        audit("command_" + ("approve" if decisao == "aprovar" else "deny"), str(cid))
        log("command_decision", "notice", cmd_id=str(cid), decision=decisao)
        return redirect(url_for("comandos"))

    # ------------------------------------------------------------------ agenda da bomba
    @app.route("/agenda", methods=["GET", "POST"])
    @login_required("agenda" if not LEGADO else "ver_painel")
    def agenda():
        if request.method == "POST":
            site, windows = request.form.get("site", ""), request.form.get("windows", "").replace(" ", "")
            err = validate_windows(windows) if not LEGADO else None
            if site not in ("escola", "horta") or err:
                log("input_rejected", "warning", field="schedule", site=site, windows=windows, reason=err)
                flash(err or "Espaço inválido.")
                return redirect(url_for("agenda"))
            query("UPDATE ops.pump_schedule SET windows=%s, updated_by=%s, updated_at=now() WHERE site=%s",
                  (windows, session["user"], site))
            log("schedule_changed", "notice", site=site, windows=windows)
            flash("Agenda atualizada. A borda validará antes de aplicar.")
            return redirect(url_for("agenda"))
        return render_template("agenda.html", rows=query("SELECT * FROM ops.pump_schedule ORDER BY site"))

    @app.get("/auditoria")
    @login_required("ver_auditoria")
    def auditoria():
        rows = query("SELECT ts, actor, action, target, ip, detail FROM audit.log ORDER BY id DESC LIMIT 200")
        return render_template("auditoria.html", rows=rows)

    # ------------------------------------------------------------------ console do SOC (RT-13/15)
    @app.get("/soc")
    @login_required("ver_soc")
    def soc():
        alerts = query("SELECT id, ts, event_ts, rule_id, level, description, groups, mitre, location FROM soc.alerts "
                       "ORDER BY ts DESC LIMIT 100")
        actions = query("SELECT a.id, a.ts, a.action, a.target, a.risk, a.status, a.result, a.decided_by, "
                        "a.alert_id, al.description AS alerta FROM soc.actions a "
                        "LEFT JOIN soc.alerts al ON al.id = a.alert_id ORDER BY a.ts DESC LIMIT 100")
        return render_template("soc.html", alerts=alerts, actions=actions)

    @app.post("/soc/acoes/<int:aid>")
    @login_required("aprovar")
    def soc_decidir(aid):
        decisao = "aprovada" if request.form.get("decisao") == "aprovar" else "negada"
        n = query("UPDATE soc.actions SET status=%s, decided_by=%s, decided_at=now() "
                  "WHERE id=%s AND status='aguardando_aprovacao'", (decisao, session["user"], aid))
        if n:
            audit("soc_action_" + decisao, str(aid))
            log("soc_action_decision", "notice", action_id=aid, decision=decisao)
        return redirect(url_for("soc"))

    @app.get("/seguranca")
    @login_required()
    def seguranca():
        return render_template("seguranca.html")

    @app.get("/healthz")
    def healthz():
        return "ok"

    @app.errorhandler(403)
    def e403(_e):
        return render_template("erro.html", msg="Seu perfil não tem acesso a esta página."), 403

    @app.errorhandler(404)
    def e404(_e):
        return render_template("erro.html", msg="Página não encontrada."), 404

    @app.errorhandler(500)
    def e500(_e):
        return render_template("erro.html", msg="Algo deu errado. Tente novamente."), 500

    return app


def repo_sites():
    return ("centro", "escola", "ubs", "horta", "abrigo")


def validate_windows(windows: str) -> str | None:
    """Mesma política aplicada na borda: mínimo 2h/dia, janelas válidas."""
    if not WINDOWS_RE.fullmatch(windows):
        return "Formato: HH:MM-HH:MM, separados por vírgula."
    total = 0
    for w in windows.split(","):
        a, b = w.split("-")
        ma, mb = int(a[:2]) * 60 + int(a[3:]), int(b[:2]) * 60 + int(b[3:])
        if not (0 <= ma < mb <= 1440) or int(a[3:]) > 59 or int(b[3:]) > 59:
            return f"Janela inválida: {w}"
        total += mb - ma
    if total < 120:
        return "A agenda precisa garantir pelo menos 2 horas de bombeamento por dia."
    return None
