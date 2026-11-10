# Autenticação de e-mail do domínio vilaaurora.test (RT-10)

Registros publicados no DNS do laboratório (CoreDNS, `phishing/out/db.vilaaurora.test`):

- `vilaaurora.test` TXT `v=spf1 ip4:172.30.50.10 -all`
- `va2026._domainkey.vilaaurora.test` TXT `v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAn3mzHhyKbhQxZOjHRgDdrY/3IWtM4ndcZbKW5+Lk+ZL7gBnU…`
- `_dmarc.vilaaurora.test` TXT `v=DMARC1; p=quarantine; pct=100; adkim=s; aspf=s; rua=mailto:dmarc-rua@vilaaurora.test; fo=1`

| Caso | Domínio do From | IP de origem | SPF | DKIM | DMARC | Ação do receptor |
|---|---|---|---|---|---|---|
| 1. Legítimo (servidor oficial + DKIM) | vilaaurora.test | 172.30.50.10 | pass | pass | pass | entregar |
| 2. Spoofing do domínio | vilaaurora.test | 203.0.113.66 | fail | none | fail | aplicar p=quarantine |
| 3a. Adulterado, saindo do servidor oficial | vilaaurora.test | 172.30.50.10 | pass | fail | pass | entregar |
| 3b. Adulterado e reenviado por terceiro | vilaaurora.test | 203.0.113.66 | fail | fail | fail | aplicar p=quarantine |
| 4. Domínio parecido | vilaaurora-painel.test | 203.0.113.66 | none | none | none | sem política (domínio não protegido) |

No caso 3a o DKIM detecta a adulteração, mas o DMARC passa porque o SPF está alinhado (basta um dos
dois mecanismos). Isso é o comportamento esperado do padrão; o 3b mostra a adulteração feita fora do servidor oficial.

Conclusão: SPF/DKIM/DMARC impedem o uso do **nosso** domínio por terceiros (casos 2 e 3b), mas não
impedem domínios parecidos (caso 4, o vetor do INC-VA-0712). Para esse caso valem o banner de remetente
externo, a triagem por IA, o treinamento e a verificação fora de banda.
