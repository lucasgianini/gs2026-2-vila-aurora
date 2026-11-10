# Vila Aurora — atalhos do laboratório (IaC: tudo reproduzível a partir do repo)
SITES := centro escola ubs horta abrigo
SHELL := /bin/bash

.PHONY: help bootstrap dirs up down logs ps status clean

help:
	@grep -E '^[a-z-]+:.*##' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-12s %s\n", $$1, $$2}'

bootstrap: ## gera segredos (.env), PKI completa e diretórios de dados
	scripts/gen-secrets.sh
	pki/pki.sh bootstrap
	$(MAKE) dirs

dirs:
	@mkdir -p data/control $(foreach s,$(SITES),data/$(s)/broker data/$(s)/edge data/$(s)/logs)
	@[ -f data/control/faults.json ] || echo '{}' > data/control/faults.json

up: dirs ## sobe o laboratório
	docker compose up -d --build

down: ## derruba (mantém dados)
	docker compose down

ps:
	docker compose ps

logs: ## segue os logs
	docker compose logs -f --tail=50

status: ## status das bordas (painéis locais)
	@for p in 8081 8082 8083 8084 8085; do curl -s -m3 localhost:$$p/api/status | \
	  python3 -c 'import sys,json;d=json.load(sys.stdin);print(d["edge"],d["link"],"outbox=",d["outbox_depth"],"alarmes=",list(d["alarms"]))'; done

clean: ## APAGA dados de runtime (não apaga PKI)
	docker compose down -v
	rm -rf data
