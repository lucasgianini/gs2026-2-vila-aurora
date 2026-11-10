"""Verifica SPF, DKIM e DMARC do domínio fictício vilaaurora.test contra o DNS do laboratório (RT-10).

Casos:
  1. E-mail legítimo: enviado pelo servidor oficial (172.30.50.10) e assinado com DKIM  -> DMARC pass
  2. Spoofing do domínio: From vilaaurora.test, enviado de outro IP, sem assinatura      -> DMARC fail -> quarentena
  3. Mensagem assinada mas ALTERADA no caminho                                           -> DKIM fail
  4. Domínio parecido (vilaaurora-painel.test, como no incidente): sem SPF/DMARC          -> sem proteção do domínio;
     depende de banner "remetente externo" + triagem (por isso o controle é em camadas)
Uso: .venv/bin/python phishing/check_email_auth.py
"""
from __future__ import annotations

import ipaddress
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

import dkim
import dns.resolver

ROOT = Path(__file__).resolve().parents[1]
R = dns.resolver.Resolver(configure=False)
R.nameservers, R.port = ["127.0.0.1"], 5354
KEY = (ROOT / "secrets/dkim/va2026.key").read_bytes()


def txt(name: str) -> list[str]:
    try:
        return [b"".join(r.strings).decode() for r in R.resolve(name, "TXT")]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
        return []


def dnsfunc(name, timeout=5):
    n = name.decode().rstrip(".")
    v = txt(n)
    return v[0].encode() if v else b""


def spf(domain: str, ip: str) -> str:
    rec = next((t for t in txt(domain) if t.startswith("v=spf1")), None)
    if not rec:
        return "none"
    for term in rec.split()[1:]:
        if term.startswith("ip4:") and ipaddress.ip_address(ip) in ipaddress.ip_network(term[4:], strict=False):
            return "pass"
        if term in ("-all", "~all"):
            return "fail" if term == "-all" else "softfail"
    return "neutral"


def dmarc(from_domain: str, spf_res: str, spf_domain: str, dkim_ok: bool, dkim_domain: str | None) -> tuple[str, str]:
    rec = next((t for t in txt(f"_dmarc.{from_domain}") if t.startswith("v=DMARC1")), None)
    if not rec:
        return "none", "sem política (domínio não protegido)"
    tags = dict(x.strip().split("=", 1) for x in rec.split(";") if "=" in x)
    strict_s, strict_d = tags.get("aspf") == "s", tags.get("adkim") == "s"
    align = lambda d, s: d == from_domain if s else (d or "").endswith(from_domain)  # noqa: E731
    ok = (spf_res == "pass" and align(spf_domain, strict_s)) or (dkim_ok and align(dkim_domain, strict_d))
    return ("pass", "entregar") if ok else ("fail", f"aplicar p={tags.get('p')}")


def make(from_addr: str, subject: str, body: str, sign: bool) -> bytes:
    m = EmailMessage()
    m["From"], m["To"], m["Subject"] = from_addr, "voluntarios@vilaaurora.test", subject
    m["Date"], m["Message-ID"] = formatdate(), make_msgid(domain="vilaaurora.test")
    m.set_content(body)
    raw = m.as_bytes()
    if sign:
        raw = dkim.sign(raw, b"va2026", b"vilaaurora.test", KEY,
                        include_headers=[b"from", b"to", b"subject", b"date", b"message-id"]) + raw
    return raw


def evaluate(name: str, raw: bytes, ip: str, envelope_domain: str) -> str:
    from_domain = raw.split(b"From: ", 1)[1].split(b"\n", 1)[0].decode().split("@")[1].strip(" >\r")
    s = spf(envelope_domain, ip)
    dk_ok = bool(dkim.verify(raw, dnsfunc=dnsfunc)) if b"DKIM-Signature" in raw else False
    dk_dom = "vilaaurora.test" if b"d=vilaaurora.test" in raw else None
    dres, action = dmarc(from_domain, s, envelope_domain, dk_ok, dk_dom)
    dk_txt = "pass" if dk_ok else ("fail" if b"DKIM-Signature" in raw else "none")
    return f"| {name} | {from_domain} | {ip} | {s} | {dk_txt} | {dres} | {action} |"


def main():
    rows = ["# Autenticação de e-mail do domínio vilaaurora.test (RT-10)", "",
            "Registros publicados no DNS do laboratório (CoreDNS, `phishing/out/db.vilaaurora.test`):", "",
            *[f"- `{n}` TXT `{(txt(n) or ['—'])[0][:110]}{'…' if len((txt(n) or [''])[0]) > 110 else ''}`"
              for n in ("vilaaurora.test", "va2026._domainkey.vilaaurora.test", "_dmarc.vilaaurora.test")],
            "", "| Caso | Domínio do From | IP de origem | SPF | DKIM | DMARC | Ação do receptor |",
            "|---|---|---|---|---|---|---|"]
    legit = make("coordenacao@vilaaurora.test", "Escala de dezembro", "A escala está no mural.", sign=True)
    rows.append(evaluate("1. Legítimo (servidor oficial + DKIM)", legit, "172.30.50.10", "vilaaurora.test"))
    spoof = make("coordenacao@vilaaurora.test", "Atualização obrigatória", "Texto de teste.", sign=False)
    rows.append(evaluate("2. Spoofing do domínio", spoof, "203.0.113.66", "vilaaurora.test"))
    tampered = legit.replace(b"A escala est", b"A senha est")
    rows.append(evaluate("3a. Adulterado, saindo do servidor oficial", tampered, "172.30.50.10", "vilaaurora.test"))
    rows.append(evaluate("3b. Adulterado e reenviado por terceiro", tampered, "203.0.113.66", "vilaaurora.test"))
    look = make("suporte@vilaaurora-painel.test", "Atualização obrigatória", "Texto de teste.", sign=False)
    rows.append(evaluate("4. Domínio parecido", look, "203.0.113.66", "vilaaurora-painel.test"))
    rows += ["", "No caso 3a o DKIM detecta a adulteração, mas o DMARC passa porque o SPF está alinhado (basta um dos",
             "dois mecanismos). Isso é o comportamento esperado do padrão; o 3b mostra a adulteração feita fora do servidor oficial.", "",
             "Conclusão: SPF/DKIM/DMARC impedem o uso do **nosso** domínio por terceiros (casos 2 e 3b), mas não",
             "impedem domínios parecidos (caso 4, o vetor do INC-VA-0712). Para esse caso valem o banner de remetente",
             "externo, a triagem por IA, o treinamento e a verificação fora de banda."]
    out = ROOT / "docs/evidencias/email_spf_dkim_dmarc.md"
    out.write_text("\n".join(rows) + "\n")
    print("\n".join(rows))


if __name__ == "__main__":
    main()
