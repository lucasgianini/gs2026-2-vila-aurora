# Reprodutibilidade a partir de clone limpo (C9)

Validação de que o laboratório sobe do zero só com o que está versionado — nenhum segredo no repo.

## Procedimento

```bash
git clone <repo> clone-test && cd clone-test
make bootstrap     # gera .env, PKI e chaves WireGuard
docker compose --profile legado --profile phishing config -q
docker compose build
```

## Resultado

| Verificação | Resultado |
|---|---|
| Clone contém apenas fonte (sem `.env`, `pki/out`, `data`, `secrets`, `vpn/out`) | **confirmado** |
| `make bootstrap` gera a PKI | **36 certificados** emitidos |
| `make bootstrap` gera as chaves WireGuard | **18 configs** (.conf) |
| `make bootstrap` gera os segredos | `.env` com 9 variáveis |
| `docker compose config` resolve todas as variáveis | **OK** |
| Build de todas as imagens próprias | **OK** (site, vpn, soar, painel, ingest) |

Observação: o `docker compose up` não foi executado no clone por conflito de portas com o laboratório
já em execução (mesmas portas em `localhost`), mas é o mesmo arquivo compose que está no ar. A
reprodução completa é `make bootstrap && make up` em uma máquina sem o laboratório rodando.
