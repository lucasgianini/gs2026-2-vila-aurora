# sqlmap para o teste "antes/depois" do RT-08 — usado SOMENTE contra os painéis deste laboratório
# (tests/t01_sqli_antes_depois.sh), em redes Docker internas.
FROM python:3.12-alpine
RUN apk add --no-cache curl && pip install --no-cache-dir sqlmap==1.9.11
WORKDIR /work
ENTRYPOINT []
CMD ["sqlmap", "--version"]
