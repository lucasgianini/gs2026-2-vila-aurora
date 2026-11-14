# Acessibilidade do Painel (RT-21)

O painel é usado por voluntários **não técnicos**, então foi feito para ser acessível e simples,
tendo como referência as diretrizes **WCAG 2.1 nível AA** e a linguagem simples em português.

## 1. O que foi implementado

| Diretriz (WCAG) | Como foi atendida | Onde |
|---|---|---|
| Contraste mínimo (1.4.3 AA) | Tema claro: texto principal **16.3:1**, destaque **8.4:1**, erro **8.1:1**, secundário **7.1:1**; etiquetas coloridas ≥ **6.8:1**. Tema escuro (segue `prefers-color-scheme`): todos os pares ≥ **6.3:1** (mínimo AA é 4.5:1). Borda dos campos ≥ **4.7:1** (1.4.11 pede 3:1) | `static/style.css` |
| Idioma da página (3.1.1) | `<html lang="pt-BR">` | `templates/base.html` |
| Navegação por teclado (2.1.1) | Só HTML nativo (links, formulários, botões); foco visível com contorno amarelo e anel de contraste; página atual marcada com `aria-current` no menu | `style.css` (`:focus-visible`) |
| Pular para o conteúdo (2.4.1) | Link "Pular para o conteúdo" no topo de cada página | `base.html` (`.skip`) |
| Rótulos em formulários (1.3.1, 3.3.2) | Todo campo visível tem `<label for=...>` associado (10 rótulos) | todos os `templates/*.html` |
| Cabeçalhos de tabela (1.3.1) | `<th scope="col">` em todas as tabelas (45 ocorrências) e `<caption>` nos resultados | `index.html`, `acessos.html`, etc. |
| Estrutura semântica (1.3.1) | `header`, `nav`, `main`, `section` com `aria-label`/`aria-labelledby`; hierarquia de `h1`→`h3` | `base.html`, `index.html` |
| Mensagens de status (4.1.3) | `role="status"` em avisos e `role="alert"` em erros | `base.html`, `acessos.html` |
| Reflow / responsivo (1.4.10) | `meta viewport`, layout em grade flexível; usável em celular | `style.css` |
| Entrada de dados (1.3.5) | `autocomplete` apropriado; código MFA com `inputmode="numeric"` e `one-time-code` | `login.html`, `mfa.html` |
| Não depender só de cor (1.4.1) | Gravidade, risco e situação aparecem como etiqueta com texto, não só cor | `_ui.html`, `index.html`, `comandos.html`, `soc.html` |

## 2. Linguagem simples

O texto evita jargão: "Entrar", "Reconhecer", "Histórico de acessos", "Agenda da bomba". A página
**Segurança** explica, em passos curtos, como reagir a um pedido urgente suspeito — pensada para a
situação do INC-VA-0712 (e-mail e áudio falsos), em linguagem de quem não é da área técnica.

## 3. Verificação

- **Contrastes** medidos pela fórmula de luminância relativa da WCAG (valores na tabela acima).
- **Estrutura** conferida por inspeção dos templates (rótulos, `scope`, marcos, hierarquia de títulos).
- Recomenda-se, antes de produção, uma passagem com **axe DevTools** ou **Lighthouse** no navegador e
  um teste com leitor de tela (NVDA/Orca) — fora do escopo do protótipo, mas no plano de manutenção.

## 4. Limite assumido

O protótipo prioriza clareza e navegação por teclado/leitor de tela. Recursos avançados (tema de alto
contraste selecionável, tamanho de fonte ajustável na própria interface) ficam como melhoria futura;
o navegador do usuário já permite ampliar a página sem quebra de layout (reflow testado).
