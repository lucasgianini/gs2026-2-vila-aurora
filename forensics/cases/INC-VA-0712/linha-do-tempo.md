# Linha do tempo — INC-VA-0712 (RT-14)

Reconstruída a partir das evidências coletadas (ver cadeia de custódia). Todos os horários em UTC.
O sincronismo por NTP em todos os nós é o que torna esta correlação confiável — ao contrário do
incidente original, em que os relógios estavam dessincronizados.

| # | Horário (UTC) | Fonte | Sev. | Evento |
|---|---|---|---|---|
| 1 | 16:52:21.000 | postgresql | alto | SQL executado: statement: SELECT ts, site, device, pseudonimo, granted, method FROM ops.acessos WHERE device LIKE '%x' UNION SELECT now |
| 2 | 16:52:21.000 | postgresql | alto | SQL executado: statement: SELECT ts, site, device, pseudonimo, granted, method FROM ops.acessos WHERE device LIKE '%x'; UPDATE ops.pump |
| 3 | 16:52:22.514 | borda-escola | alto | RECUSOU comando: set_schedule em escola-bomba — agenda com menos de 2h/dia de bombeamento |
| 4 | 16:52:37.543 | borda-escola | medio | Agenda alterada: 05:00-07:00,17:00-19:00 |
| 5 | 16:52:52.575 | borda-escola | medio | Comando aceito: off em escola-bomba (origem remote:carla.tec) |
| 6 | 17:12:27.287 | borda-escola | medio | Comando aceito: on em escola-bomba (origem edge-rule) |
| 7 | 17:12:38.034 | borda-escola | medio | Comando aceito: off em escola-bomba (origem edge-rule) |
| 8 | 17:29:39.159 | SIEM | alto | ALERTA regra 100300 (nvl 10): (c) Broker MQTT recusou cliente sem certificado válido (error:0A0000C7:SSL routi [MITRE T1557,T0848] |
| 9 | 17:43:15.000 | borda-escola | alto | RECUSOU comando: set_schedule em escola-bomba — TESTE DE PLAYBOOK |
| 10 | 17:43:15.965 | SIEM | alto | ALERTA regra 100403 (nvl 12): (d) Borda escola RECUSOU comando inseguro: set_schedule em escola-bomba por dieg |
| 11 | 17:43:17.144 | SOAR | medio | Resposta executed: modo_seguro -> escola-bomba (comando safe_mode enfileirado p/ escola-) |
| 12 | 17:43:17.153 | SOAR | medio | Resposta executed: bloquear_conta -> diego.op (conta diego.op bloqueada por 24 h) |
| 13 | 17:43:31.981 | SIEM | alto | ALERTA regra 100304 (nvl 12): (c) Dispositivo publicou dados em nome de outro (escola-teste-soar) em escola |
| 14 | 17:43:33.164 | SOAR | medio | Resposta executed: isolar_dispositivo -> escola-teste-soar (comando isolate enfileirado p/ escola-te) |
| 15 | 17:43:33.182 | SOAR | medio | Resposta executed: revogar_certificado -> escola-teste-soar (certificado escola-teste-soar revogado; ) |
| 16 | 17:43:43.000 | VPN-legada | alto | Autenticação OK na VPN legada (só senha): usuário marta.coord de 172.30.99.66 |
| 17 | 17:43:43.993 | SIEM | alto | ALERTA regra 100112 (nvl 13): (a) VPN legada: login de origem desconhecida de madrugada (marta.coord, 172.30.9 [MITRE T1133,T1078] |
| 18 | 17:43:45.196 | SOAR | medio | Resposta executed: bloquear_ip -> 172.30.99.66 (bloqueado 172.30.99.66) |
| 19 | 17:43:45.201 | SOAR | medio | Resposta executed: bloquear_conta -> marta.coord (conta marta.coord bloqueada por 24 h) |
| 20 | 17:43:45.204 | SOAR | medio | Resposta proposed: encerrar_todas_sessoes_vpn -> wg2 (aguardando aprovação humana) |
| 21 | 17:49:56.000 | VPN-legada | alto | Autenticação OK na VPN legada (só senha): usuário marta.coord de 172.30.99.66 |
| 22 | 17:49:58.360 | SIEM | alto | ALERTA regra 100112 (nvl 13): (a) VPN legada: login de origem desconhecida de madrugada (marta.coord, 172.30.9 [MITRE T1133,T1078] |
| 23 | 17:49:59.937 | SOAR | medio | Resposta executed: bloquear_ip -> 172.30.99.66 (bloqueado 172.30.99.66) |
| 24 | 17:49:59.945 | SOAR | medio | Resposta executed: bloquear_conta -> marta.coord (conta marta.coord bloqueada por 24 h) |
| 25 | 17:49:59.948 | SOAR | medio | Resposta proposed: encerrar_todas_sessoes_vpn -> wg2 (aguardando aprovação humana) |
| 26 | 18:18:28.474 | borda-escola | medio | Comando aceito: on em escola-bomba (origem edge-rule) |
| 27 | 18:20:03.712 | borda-escola | medio | Comando aceito: off em escola-bomba (origem edge-rule) |
| 28 | 18:24:31.000 | VPN-legada | alto | Autenticação OK na VPN legada (só senha): usuário diego.op de 172.30.99.66 |
| 29 | 18:24:32.429 | SIEM | alto | ALERTA regra 100111 (nvl 12): (a) VPN legada: diego.op autenticou de IP externo desconhecido 172.30.99.66 [MITRE T1133,T1078] |
| 30 | 18:24:32.927 | SOAR | medio | Resposta executed: bloquear_ip -> 172.30.99.66 (bloqueado 172.30.99.66) |
| 31 | 18:24:32.933 | SOAR | medio | Resposta executed: bloquear_conta -> diego.op (conta diego.op bloqueada por 24 h) |
| 32 | 18:24:41.229 | borda-escola | medio | Comando aceito: on em escola-bomba (origem edge-rule) |
| 33 | 18:24:58.000 | painel-legado | info | HTTP GET / (status 400) |
| 34 | 18:25:25.000 | VPN-legada | alto | Autenticação OK na VPN legada (só senha): usuário diego.op de 172.30.99.66 |
| 35 | 18:25:26.483 | SIEM | alto | ALERTA regra 100111 (nvl 12): (a) VPN legada: diego.op autenticou de IP externo desconhecido 172.30.99.66 [MITRE T1133,T1078] |
| 36 | 18:25:31.000 | painel-legado | info | HTTP GET /login (status 200) |
| 37 | 18:25:31.000 | painel-legado | info | HTTP POST /login (status 302) |
| 38 | 18:25:31.000 | painel-legado | alto | HTTP GET /acessos?q=x%27+UNION+SELECT+now%28%29%2cnome%2cemail%2ctelefone%2ctrue%2cpapel+FROM+cadas (status 200) [padrão SQLi] |
| 39 | 18:25:31.000 | painel-legado | alto | HTTP GET /acessos?q=x%27%3b+UPDATE+ops.pump_schedule+SET+windows%3d%2703%3a00-03%3a05%27%2c+updated (status 200) [padrão SQLi] |
| 40 | 18:25:31.000 | postgresql | alto | SQL executado: statement: SELECT ts, site, device, pseudonimo, granted, method FROM ops.acessos WHERE device LIKE '%x' UNION SELECT now |
| 41 | 18:25:31.000 | postgresql | alto | SQL executado: statement: SELECT ts, site, device, pseudonimo, granted, method FROM ops.acessos WHERE device LIKE '%x'; UPDATE ops.pump |
| 42 | 18:25:31.755 | borda-escola | alto | RECUSOU comando: set_schedule em escola-bomba — agenda com menos de 2h/dia de bombeamento |
| 43 | 18:25:32.489 | SIEM | alto | ALERTA regra 100200 (nvl 12): (b) Padrão de SQL Injection na requisição ao painel de 172.30.30.135: /acessos?q [MITRE T1190] |
| 44 | 18:25:32.489 | SIEM | alto | ALERTA regra 100204 (nvl 13): (b) Banco executou SQL injetado pelo painel legado: statement: SELECT ts, site,  [MITRE T1190,T1565.001] |
| 45 | 18:25:32.489 | SIEM | alto | ALERTA regra 100200 (nvl 12): (b) Padrão de SQL Injection na requisição ao painel de 172.30.30.135: /acessos?q [MITRE T1190] |
| 46 | 18:25:32.489 | SIEM | alto | ALERTA regra 100403 (nvl 12): (d) Borda escola RECUSOU comando inseguro: set_schedule em escola-bomba por dieg |
| 47 | 18:25:32.489 | SIEM | alto | ALERTA regra 100204 (nvl 13): (b) Banco executou SQL injetado pelo painel legado: statement: SELECT ts, site,  [MITRE T1190,T1565.001] |
| 48 | 18:25:32.979 | SOAR | medio | Resposta executed: modo_seguro -> escola-bomba (comando safe_mode enfileirado p/ escola-) |
| 49 | 18:25:41.789 | borda-escola | medio | Agenda alterada: 05:00-07:00,17:00-19:00 |
| 50 | 18:26:05.134 | borda-escola | medio | Comando aceito: off em escola-bomba (origem edge-rule) |
| 51 | 18:31:18.946 | borda-escola | medio | Comando aceito: on em escola-bomba (origem edge-rule) |

**Janela do incidente:** 2026-11-10 16:52:21 a 18:31:18 UTC (5938 s, 51 eventos correlacionados).
