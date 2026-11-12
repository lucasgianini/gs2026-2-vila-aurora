# Plano de Conscientização dos Voluntários (RT-11 · RT-18 · C4)

Complementa os controles técnicos de e-mail (SPF/DKIM/DMARC, triagem por IA) com o único controle
que funciona contra **domínio parecido** e **voz clonada** — os dois vetores do INC-VA-0712 que a
tecnologia não barra sozinha: a pessoa que recebe o pedido.

## 1. Para quem é

O plano foi escrito para a realidade da Rede Vila Aurora, não para uma empresa:

| Público | Características | Risco principal |
|---|---|---|
| Coordenação (2 pessoas) | Têm poder de aprovar ações de alto impacto; são conhecidas publicamente | Alvo direto de e-mail "da prefeitura" e de **voz clonada** de autoridade |
| Técnicos voluntários | Acesso à VPN administrativa e ao painel | Pedido "urgente" de liberar acesso remoto ou instalar algo |
| Operadores dos espaços | Usam o painel no dia a dia, pouca formação técnica | Link falso de "atualização obrigatória do acesso" |
| Voluntários ocasionais | Rotatividade alta, pouco tempo, usam o próprio celular | Mensagem de WhatsApp pedindo dados de moradores ou código recebido por SMS |

Restrições assumidas: ninguém tem tempo para curso longo, parte do grupo tem baixa familiaridade
digital, e o treinamento não pode virar motivo de constrangimento — quem tem medo de bronca não reporta.

## 2. As cinco regras (o conteúdo inteiro cabe num cartaz)

1. **Pressa é sinal de golpe.** "Urgente", "obrigatório", "hoje": pare antes de agir.
2. **Texto bem escrito e voz conhecida não provam nada.** Os dois podem ser feitos por inteligência artificial.
3. **Ligue de volta** para o número que está no cadastro da coordenação — nunca para o que veio na mensagem.
4. **Peça a palavra-código.** Quem não sabe a palavra do mês não é da equipe.
5. **Nunca digite a senha a partir de um link.** Entre pelo endereço salvo. Achou estranho? Reporte — reportar nunca é motivo de bronca.

As mesmas regras estão na página **Segurança** do painel (`cloud/painel/app/templates/seguranca.html`),
em linguagem simples e navegável por teclado (RT-21).

## 3. Procedimento para pedido urgente (contra voz clonada)

Vale para qualquer pedido fora da rotina que chegue por e-mail, WhatsApp, áudio ou ligação — inclusive
se a voz for de alguém conhecido:

1. **Não execute na hora** e não continue a conversa no mesmo canal.
2. **Verificação fora de banda:** ligue para o número da pessoa que consta no cadastro da coordenação
   (lista impressa em cada espaço), ou fale pessoalmente.
3. **Palavra-código:** peça a palavra do mês. Ela é combinada **presencialmente** na reunião mensal,
   trocada todo mês, e nunca é escrita em e-mail ou mensagem.
4. **Sem confirmação, não faz.** Registre o pedido no painel e avise a coordenação.
5. Ações de alto impacto (desligar bomba, liberar todas as portas) já exigem, no sistema, a aprovação de
   uma segunda pessoa (RT-15): mesmo que alguém seja enganado, uma pessoa só não consegue executar.

## 4. Como o conteúdo chega às pessoas

| Ação | Formato | Duração | Frequência | Responsável |
|---|---|---|---|---|
| Acolhida de novo voluntário | Conversa com o cartaz + 2 exemplos reais (e-mail e áudio) | 15 min | Na entrada | Coordenação de voluntários |
| Cartaz das cinco regras | Impresso, letra grande, em cada espaço | — | Permanente | Coordenação |
| Momento de segurança | Um caso comentado na reunião mensal + troca da palavra-código | 10 min | Mensal | Coordenação |
| Lembrete curto | Mensagem de texto **e áudio** no grupo dos voluntários | 1 min | Quinzenal | Técnico voluntário |
| Simulação de phishing | Campanha Gophish (seção 5) | — | Trimestral | Técnico voluntário |
| Demonstração de voz sintética | Áudio de integrante **com consentimento por escrito**, identificado como sintético | 5 min | Semestral | Coordenação |
| Reforço para quem clicou | Conversa individual, sem exposição, com os sinais que passaram despercebidos | 5 min | Após cada campanha | Coordenação |

Acessibilidade: frases curtas, sem jargão, material também em áudio, exemplos do cotidiano da rede
(prefeitura, doação, escala de voluntários) em vez de exemplos corporativos.

## 5. Simulações de phishing — regras éticas

- Somente com **aviso prévio geral** ("ao longo do ano faremos simulações") e ciência da coordenação;
  com voluntários reais, só mediante **consentimento**.
- A página de destino **não captura credenciais** (`capture_credentials=false`); mede apenas abertura,
  clique e reporte. Quem clica cai numa página educativa com as cinco regras.
- Resultados individuais ficam restritos à coordenação e nunca são divulgados nem usados para punir.
- No protótipo, a campanha rodou **apenas contra 16 contas fictícias** (`voluntarioNN@vilaaurora.test`)
  com comportamento simulado por perfil — nenhuma pessoa real foi alvo (`docs/evidencias/phishing_campanha.md`).

## 6. Metas e indicadores

A linha de base abaixo vem da campanha de laboratório. Como o comportamento foi **simulado**, ela valida
o processo de medição, não o comportamento real: a primeira campanha com voluntários (com consentimento)
substitui esses números.

| Indicador | Linha de base (lab.) | Meta em 6 meses | Meta em 12 meses |
|---|---|---|---|
| Taxa de clique | 31% | ≤ 20% | ≤ 10% |
| Taxa de reporte | 12% | ≥ 30% | ≥ 50% |
| Envio de dados na página | 0% (página não coleta) | 0% | 0% |
| Tempo até o primeiro reporte | não medido | ≤ 30 min | ≤ 10 min |
| Voluntários que passaram pela acolhida | — | 100% dos novos | 100% de todos |
| Pedidos urgentes confirmados fora de banda | — | registrar todos | 100% |

O reporte é o indicador mais importante: um único reporte rápido permite à coordenação avisar todos
antes que mais alguém clique. Queda de clique sem aumento de reporte indica apenas que o modelo de
e-mail da simulação ficou conhecido.

## 7. O que acontece quando alguém reporta

1. O voluntário usa o botão "Reportar phishing" ou avisa a coordenação.
2. O e-mail passa pela triagem por IA (`cloud/ai/triagem_llm.py`), que só rotula — a decisão é humana.
3. Confirmado o golpe: aviso no grupo em até 30 minutos, bloqueio do remetente e, se alguém digitou
   a senha, troca imediata da senha e encerramento das sessões (VPN e painel).
4. Quem reportou recebe um agradecimento. O caso vira o exemplo da próxima reunião mensal.

## 8. Cronograma do primeiro ano

| Mês | Atividade |
|---|---|
| 1 | Cartazes nos cinco espaços; lista de telefones impressa; primeira palavra-código; acolhida de todos os voluntários ativos |
| 2 | Primeira simulação real (com consentimento) — nova linha de base |
| 3 | Reforço individual; ajuste do material conforme as dúvidas |
| 5, 8, 11 | Simulações trimestrais com modelos diferentes (doação, escala, "prefeitura") |
| 6 | Demonstração de voz sintética; revisão das metas |
| 12 | Balanço anual apresentado à associação; revisão do plano |

Custo: material impresso (R$ 240/ano, em `docs/03-custos-manutencao.md`) e horas de voluntariado.
