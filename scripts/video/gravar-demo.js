// Gravador do vídeo de demonstração (E2/C9): cada quadro é uma captura real da plataforma, com
// cursor estilo Windows desenhado por cima; 1920x1080 a 60 fps (h264). Pré-requisito: make up,
// perfil legado e Node 20+.  Uso: cd scripts/video && npm install && npx playwright install chromium && node gravar-demo.js ../../entrega/demo.mp4 [cena,...]
const { chromium } = require('playwright');
const { spawn } = require('child_process');
const fs = require('fs');
const crypto = require('crypto');

const ROOT = require('path').resolve(__dirname, '../..');
const OUT = process.argv[2] || 'out.mp4';
const ONLY = process.argv[3] ? process.argv[3].split(',') : null;
const FPS = 60, W = 1536, H = 864, DSF = 1.25;   // 1920x1080 no vídeo
const PAINEL = 'https://10.90.0.1', PORTAL = 'http://10.90.0.1:8080/', LEGADO = 'https://172.30.30.80:9443';

// ------------------------------------------------------------------ segredos de laboratório
const ops = Object.fromEntries(fs.readFileSync(`${ROOT}/secrets/operadores.txt`, 'utf8').trim().split('\n')
  .map(l => l.split(/\s+/)).map(p => [p[0], { pw: p[2].replace('senha=', ''), totp: p[3].replace('totp=', '') }]));
const vpn = Object.fromEntries(fs.readFileSync(`${ROOT}/secrets/vpn-admins.txt`, 'utf8').trim().split('\n')
  .map(l => l.split(/\s+/)).map(p => [p[0], p[2]]));
function b32(s) { const a = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'; let bits = '', out = [];
  for (const c of s.replace(/=+$/, '').toUpperCase()) bits += a.indexOf(c).toString(2).padStart(5, '0');
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2)); return Buffer.from(out); }
function totp(secret) { const c = Buffer.alloc(8); c.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = crypto.createHmac('sha1', b32(secret)).update(c).digest(); const o = h[19] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, '0'); }
async function freshTotp(secret) { // evita código prestes a expirar
  while ((Date.now() / 1000) % 30 > 24) await new Promise(r => setTimeout(r, 300)); return totp(secret); }

// ------------------------------------------------------------------ cursores (estilo Windows)
const SVG = {
  arrow: { hx: 1, hy: 1, svg: `<svg xmlns="http://www.w3.org/2000/svg" width="21" height="30.7" viewBox="0 0 13 19"><path d="M.5.5v15.6l3.7-3.6 2.4 5.7 2.3-1-2.4-5.6h5.1z" fill="#fff" stroke="#000" stroke-width="1" stroke-linejoin="round"/></svg>` },
  hand: { hx: 10.3, hy: 0.8, svg: `<svg xmlns="http://www.w3.org/2000/svg" width="30" height="36.3" viewBox="0 0 19 23"><path d="M6.5.5c1.1 0 2 .9 2 2v5.1c.3-.4.8-.6 1.3-.6.9 0 1.6.5 1.8 1.2.3-.3.8-.5 1.3-.5.9 0 1.6.6 1.8 1.4.3-.2.7-.3 1.1-.3 1.1 0 1.7.8 1.7 1.8V15c0 2.5-1 4-2 5.5v2h-8v-1.7C6 19.5 3.5 16.5 1.3 13.6c-.7-.9-.5-2.1.4-2.7.9-.6 2-.3 2.7.5l.1.1V2.5c0-1.1.9-2 2-2z" fill="#fff" stroke="#000" stroke-width="1" stroke-linejoin="round"/><path d="M8.5 7.6v4.4M11.6 8.2v3.8M14.7 9.1v2.9" stroke="#000" stroke-width=".9" stroke-linecap="round"/></svg>` },
  ibeam: { hx: 7, hy: 14, svg: `<svg xmlns="http://www.w3.org/2000/svg" width="14" height="28" viewBox="0 0 9 18"><path d="M1 1h2.5L4.5 2l1-1H8M1 17h2.5l1-1 1 1H8M4.5 2v14" fill="none" stroke="#fff" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"/><path d="M1 1h2.5L4.5 2l1-1H8M1 17h2.5l1-1 1 1H8M4.5 2v14" fill="none" stroke="#000" stroke-width="1"/></svg>` },
};
const CURSORS = Object.fromEntries(Object.entries(SVG).map(([k, v]) =>
  [k, { ...v, url: 'data:image/svg+xml;base64,' + Buffer.from(v.svg).toString('base64') }]));

// Sobreposição injetada em todo documento (cursor, legenda, cartão de título, onda de clique)
const OVERLAY = `(() => {
  const C = ${JSON.stringify(CURSORS)};
  const mk = () => {
    if (document.getElementById('__rec')) return;
    const host = document.createElement('div'); host.id = '__rec';
    Object.assign(host.style, {position:'fixed', inset:'0', zIndex:'2147483647', pointerEvents:'none'});
    const sh = host.attachShadow({mode:'open'});
    sh.innerHTML = \`<style>
      *{box-sizing:border-box;font-family:'Segoe UI','Noto Sans',system-ui,sans-serif}
      #cur{position:fixed;left:0;top:0;will-change:transform;filter:drop-shadow(0.8px 1.6px 1.2px rgba(0,0,0,.35))}
      #rip{position:fixed;width:35.2px;height:35.2px;margin:-17.6px 0 0 -17.6px;border-radius:50%;border:2.4px solid rgba(37,99,235,.85);opacity:0}
      #cap{position:fixed;left:32px;bottom:32px;max-width:720px;background:rgba(15,23,42,.92);color:#fff;border-radius:11.2px;
           padding:14.4px 19.2px 14.4px 17.6px;box-shadow:0 9.6px 25.6px rgba(0,0,0,.28);opacity:0;display:flex;gap:14.4px;align-items:flex-start;border-left:4.8px solid #38bdf8}
      #cap .tag{flex:none;background:#38bdf8;color:#082f49;font-weight:700;font-size:13.6px;padding:3.2px 8px;border-radius:5.6px;margin-top:2.4px;white-space:nowrap}
      #cap .t{font-size:19.2px;font-weight:650;line-height:1.25}
      #cap .s{font-size:14.4px;opacity:.85;margin-top:4px;line-height:1.35}
      #card{position:fixed;inset:0;background:linear-gradient(135deg,#0b2545 0%,#13315c 55%,#134e4a 100%);color:#fff;display:flex;
            flex-direction:column;justify-content:center;padding:0 128px;opacity:0}
      #card .k{font-size:19.2px;letter-spacing:.14em;text-transform:uppercase;color:#7dd3fc;font-weight:600}
      #card .h{font-size:57.6px;font-weight:750;margin:14.4px 0 11.2px;line-height:1.08}
      #card .p{font-size:24px;opacity:.88;max-width:1040px;line-height:1.4}
      #card .f{position:absolute;left:128px;bottom:72px;font-size:16px;opacity:.7}
    </style><div id="card"><div class="k"></div><div class="h"></div><div class="p"></div><div class="f"></div></div>
    <div id="cap"><span class="tag"></span><div><div class="t"></div><div class="s"></div></div></div>
    <div id="rip"></div><img id="cur">\`;
    document.documentElement.appendChild(host);
    window.__recSh = sh;
  };
  window.__rec = (st) => {
    mk(); const sh = window.__recSh, c = C[st.kind || 'arrow'], cur = sh.getElementById('cur');
    if (cur.dataset.k !== st.kind) { cur.src = c.url; cur.dataset.k = st.kind; }
    cur.style.transform = 'translate(' + (st.x - c.hx) + 'px,' + (st.y - c.hy) + 'px) scale(' + (st.press ? .9 : 1) + ')';
    cur.style.transformOrigin = c.hx + 'px ' + c.hy + 'px';
    cur.style.opacity = st.hideCursor ? 0 : 1;
    const rip = sh.getElementById('rip');
    rip.style.left = st.rx + 'px'; rip.style.top = st.ry + 'px';
    rip.style.opacity = st.rip > 0 ? (1 - st.rip) : 0; rip.style.transform = 'scale(' + (.4 + st.rip * 1.1) + ')';
    const cap = sh.getElementById('cap');
    cap.querySelector('.tag').textContent = st.cap?.tag || ''; cap.querySelector('.tag').style.display = st.cap?.tag ? '' : 'none';
    cap.querySelector('.t').textContent = st.cap?.t || ''; cap.querySelector('.s').textContent = st.cap?.s || '';
    cap.style.opacity = st.capA; cap.style.transform = 'translateY(' + ((1 - st.capA) * 14) + 'px)';
    if (st.capPos === 'top') { cap.style.bottom = 'auto'; cap.style.top = '32px'; cap.style.left = 'auto'; cap.style.right = '32px'; }
    else { cap.style.top = 'auto'; cap.style.bottom = '32px'; cap.style.right = 'auto'; cap.style.left = '32px'; }
    const card = sh.getElementById('card');
    card.style.opacity = st.cardA; card.querySelector('.k').textContent = st.card?.k || '';
    card.querySelector('.h').textContent = st.card?.h || ''; card.querySelector('.p').textContent = st.card?.p || '';
    card.querySelector('.f').textContent = st.card?.f || '';
    for (const el of card.children) { el.style.opacity = st.cardTA ?? 1; el.style.transform = 'translateY(' + ((1 - (st.cardTA ?? 1)) * 10) + 'px)'; }
  };
})();`;

// ------------------------------------------------------------------ saída de vídeo
const ff = spawn('ffmpeg', ['-y', '-loglevel', 'error', '-f', 'image2pipe', '-framerate', String(FPS), '-c:v', 'mjpeg', '-i', '-',
  '-c:v', 'libx264', '-preset', 'slow', '-crf', '15', '-tune', 'stillimage', '-pix_fmt', 'yuv420p', '-r', String(FPS),
  '-movflags', '+faststart', OUT], { stdio: ['pipe', 'inherit', 'inherit'] });
let frames = 0, last = null;
async function push(buf) { last = buf; frames++; if (!ff.stdin.write(buf)) await new Promise(r => ff.stdin.once('drain', r)); }

// ------------------------------------------------------------------ estado e primitivas
const st = { x: W / 2, y: H / 2, kind: 'arrow', press: false, rip: 0, rx: 0, ry: 0, cap: null, capA: 0, card: null, cardA: 0, hideCursor: false, capPos: 'bottom', cardTA: 1 };
let page;
const ease = t => t < .5 ? 4 * t * t * t : 1 - Math.pow(-2 * t + 2, 3) / 2;
const easeOut = t => 1 - Math.pow(1 - t, 3);
const sleep = ms => new Promise(r => setTimeout(r, ms));

async function apply() { await page.evaluate(s => window.__rec && window.__rec(s), st).catch(() => {}); }
async function shot() {
  await apply();
  const b = await page.screenshot({ type: 'jpeg', quality: 93, caret: 'initial', scale: 'device' });
  await push(b);
}
async function hold(ms) { const n = Math.round(ms / 1000 * FPS); if (!last) await shot();
  for (let i = 0; i < n; i++) await push(last); }
async function frame() { await shot(); }

async function cursorKindAt(x, y) {
  return page.evaluate(([x, y]) => {
    const h = document.getElementById('__rec'); if (h) h.style.display = 'none';
    let el = document.elementFromPoint(x, y); if (h) h.style.display = '';
    if (!el) return 'arrow';
    const c = getComputedStyle(el).cursor;
    if (c === 'pointer') return 'hand';
    if (c === 'text') return 'ibeam';
    if (c === 'auto') {
      if (el.closest('a[href],button,summary,select,label[for]')) return 'hand';
      if (el.matches('input:not([type=checkbox]):not([type=radio]):not([type=submit]):not([type=button]),textarea')) return 'ibeam';
    }
    return 'arrow';
  }, [x, y]);
}

async function moveTo(x, y, ms) {
  const x0 = st.x, y0 = st.y, d = Math.hypot(x - x0, y - y0);
  if (d < 2) return;
  ms = ms || Math.min(1100, 360 + d * 0.7);
  const n = Math.max(8, Math.round(ms / 1000 * FPS));
  // trajetória levemente curva, como a mão humana
  const bend = (Math.random() - .5) * Math.min(160, d * .22);
  const nx = -(y - y0) / (d || 1), ny = (x - x0) / (d || 1);
  const cx = (x0 + x) / 2 + nx * bend, cy = (y0 + y) / 2 + ny * bend;
  let lastKindCheck = 0;
  for (let i = 1; i <= n; i++) {
    const t = ease(i / n), u = 1 - t;
    st.x = u * u * x0 + 2 * u * t * cx + t * t * x; st.y = u * u * y0 + 2 * u * t * cy + t * t * y;
    if (i - lastKindCheck >= 6 || i === n) { lastKindCheck = i; st.kind = await cursorKindAt(st.x, st.y); }
    await page.mouse.move(st.x, st.y);
    await frame();
  }
}

async function target(sel, opts = {}) {
  const loc = typeof sel === 'string' ? page.locator(sel).first() : sel.first();
  await loc.scrollIntoViewIfNeeded().catch(() => {});
  const bb = await loc.boundingBox();
  if (!bb) throw new Error('sem caixa: ' + sel);
  const fx = opts.fx ?? (0.35 + Math.random() * 0.3), fy = opts.fy ?? (0.4 + Math.random() * 0.2);
  return [bb.x + Math.min(bb.width * fx, opts.maxX ?? 1e9), bb.y + bb.height * fy];
}
async function hover(sel, opts) { const [x, y] = await target(sel, opts); await moveTo(x, y); await hold(opts?.after ?? 180); }

async function click(sel, opts = {}) {
  const [x, y] = await target(sel, opts);
  await moveTo(x, y);
  await hold(120);
  st.press = true; st.rx = x; st.ry = y;
  for (let i = 0; i < 5; i++) { st.rip = i / 18; await frame(); }
  const nav = opts.nav ? page.waitForNavigation({ waitUntil: 'load', timeout: 20000 }).catch(() => {}) : null;
  await page.mouse.down(); await page.mouse.up();
  st.press = false;
  if (nav) { await nav; await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {}); }
  for (let i = 5; i <= 18; i++) { st.rip = i / 18; await frame(); }
  st.rip = 0; st.kind = await cursorKindAt(st.x, st.y);
  await frame();
  await hold(opts.after ?? 400);
}

async function type(text, opts = {}) {
  for (const ch of text) {
    await page.keyboard.type(ch);
    const n = opts.fast ? 3 : 4 + Math.floor(Math.random() * 4) + (ch === ' ' ? 2 : 0);
    await frame(); await hold((n - 1) * 1000 / FPS);
  }
  await hold(opts.after ?? 300);
}

async function fill(sel, text, opts) { await click(sel, { after: 150 }); await page.locator(sel).first().fill(''); await type(text, opts); }

async function scrollTo(y, ms = 1200) {
  const y0 = await page.evaluate(() => scrollY);
  const max = await page.evaluate(() => document.documentElement.scrollHeight - innerHeight);
  y = Math.max(0, Math.min(max, typeof y === 'number' ? y : 0));
  const n = Math.max(10, Math.round(ms / 1000 * FPS));
  for (let i = 1; i <= n; i++) {
    const v = y0 + (y - y0) * ease(i / n);
    await page.evaluate(v => window.scrollTo(0, v), v);
    if (i % 8 === 0 || i === n) st.kind = await cursorKindAt(st.x, st.y);
    await frame();
  }
}
async function scrollToEl(sel, offset = 120, ms) {
  const y = await page.locator(sel).first().evaluate((e, o) => e.getBoundingClientRect().top + scrollY - o, offset);
  await scrollTo(y, ms);
}

async function caption(tag, t, s, pos = 'bottom') {
  if (st.capA > 0) { for (let i = 1; i <= 12; i++) { st.capA = 1 - i / 12; await frame(); } }
  st.cap = { tag, t, s }; st.capPos = pos;
  for (let i = 1; i <= 16; i++) { st.capA = easeOut(i / 16); await frame(); }
}
async function noCaption() { if (st.capA === 0) return; for (let i = 1; i <= 12; i++) { st.capA = 1 - i / 12; await frame(); } st.cap = null; }

async function goto(url, opts = {}) {
  await page.goto(url, { waitUntil: 'load', timeout: 25000 }).catch(e => { if (!opts.allowFail) throw e; });
  await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
  st.kind = await cursorKindAt(st.x, st.y).catch(() => 'arrow');
  await frame();
}

// transição suave entre cenas (cartão por cima)
async function card(k, h, p, f, ms = 2600) {
  await noCaption();
  if (st.cardA >= 1) {   // já há um cartão: troca o texto com esmaecimento
    for (let i = 1; i <= 12; i++) { st.cardTA = 1 - i / 12; await frame(); }
    st.card = { k, h, p, f };
    for (let i = 1; i <= 16; i++) { st.cardTA = easeOut(i / 16); await frame(); }
  } else {
    st.card = { k, h, p, f }; st.hideCursor = true; st.cardTA = 1;
    for (let i = 1; i <= 24; i++) { st.cardA = ease(i / 24); await frame(); }
  }
  await hold(ms);
}
async function uncard() { for (let i = 1; i <= 24; i++) { st.cardA = 1 - ease(i / 24); await frame(); } st.card = null; st.hideCursor = false; await frame(); }

// ------------------------------------------------------------------ cenas
const SCENES = {
  async abertura() {
    await goto('data:text/html,<body style="background:%230b2545"></body>');
    await card('FIAP · Global Solution 2026.2 · Cybersecurity', 'Rede Comunitária Vila Aurora',
      'Demonstração do protótipo (E2): infraestrutura segura e resiliente para os cinco espaços comunitários — campo → borda → nuvem → supervisão.',
      'Laboratório isolado em containers Docker · dados 100% sintéticos', 3800);
    await card('Cena 1 · Acesso administrativo', 'VPN WireGuard + MFA',
      'O notebook do administrador só alcança a nuvem pelo túnel WireGuard; o acesso é liberado com o código do autenticador.', 'RT-06 · RT-07', 2400);
  },

  async vpn() {
    await goto(PORTAL);
    await page.evaluate(() => { document.body.style.zoom = '1.6'; document.body.style.marginTop = '5rem'; }); await frame();
    await uncard();
    await caption('RT-06', 'Portal de verificação da VPN (10.90.0.1)', 'Nenhuma porta administrativa exposta: o portal só existe dentro do túnel WireGuard.');
    await hold(1200);
    await fill('#u', 'bruno.coord');
    await fill('#c', await freshTotp(vpn['bruno.coord']), { fast: true });
    await click('button[type=submit]', { nav: true, after: 0 });
    await page.evaluate(() => { document.body.style.zoom = '1.6'; document.body.style.marginTop = '5rem'; }); await frame(); await hold(600);
    await caption('RT-06', 'Acesso liberado após o segundo fator', 'Código TOTP do aplicativo autenticador — senha sozinha não basta.');
    await hold(2600);
  },

  async login() {
    await card('Cena 2 · Painel de supervisão', 'Login com MFA e perfis (RBAC)',
      'Operador, técnico, coordenação e auditor — cada perfil vê apenas o que precisa.', 'RT-09 · RT-21', 2200);
    await goto(PAINEL + '/login');
    await uncard();
    await caption('RT-09', 'Entrar no painel (HTTPS com certificado da CA própria)', 'Usuário e senha + código TOTP; tentativas limitadas e bloqueio após 5 erros.');
    await fill('#username', 'bruno.coord');
    await fill('#password', ops['bruno.coord'].pw, { fast: true });
    await click('form.panel button[type=submit]', { nav: true, after: 700 });
    await caption('RT-09', 'Segundo fator obrigatório', 'Sem o código de 6 dígitos a sessão não é criada.');
    await fill('#code', await freshTotp(ops['bruno.coord'].totp), { fast: true });
    await click('form.panel button[type=submit]', { nav: true, after: 800 });
  },

  async visao() {
    await caption('RT-01 · RT-21', 'Visão geral dos cinco espaços', 'Leituras dos sensores chegam da borda por mTLS; linguagem simples, rótulos e unidades para voluntários.');
    await hold(2600);
    const h = await page.locator('h2:has-text("Alarmes ativos")').count();
    if (h) {
      await scrollToEl('h2:has-text("Alarmes ativos")', 140, 1100);
      await hold(700);
      const btn = page.locator('button:has-text("Reconhecer")');
      if (await btn.count()) {
        await caption('RT-09', 'Reconhecer um alarme', 'Ação permitida para operador, técnico e coordenação — e registrada na trilha de auditoria.');
        await click(btn, { nav: true, after: 1400 });
      }
    }
    await scrollToEl('h2:has-text("Espaços")', 120, 1400);
    await caption('RT-01', 'Espaços: Centro, Escola, UBS, Horta e Abrigo', 'Caixa d’água, bomba, câmara fria de vacinas, energia, fechaduras e qualidade do ar.');
    await hold(1200);
    const max = await page.evaluate(() => document.documentElement.scrollHeight - innerHeight);
    const y0 = await page.evaluate(() => scrollY);
    for (const f of [0.35, 0.7, 1]) { await scrollTo(y0 + (max - y0) * f, 1600); await hold(900); }
    await scrollTo(0, 1500);
    // tema escuro e navegação por teclado (acessibilidade)
    await caption('RT-21', 'Acessibilidade: tema escuro automático', 'Contraste WCAG 2.1 AA nos dois temas; segue a preferência do sistema.');
    await page.emulateMedia({ colorScheme: 'dark' }); await frame(); await hold(2200);
    await page.emulateMedia({ colorScheme: 'light' }); await frame(); await hold(500);
    await caption('RT-21', 'Navegação completa pelo teclado', 'Link “pular para o conteúdo” e foco sempre visível.');
    await moveTo(W - 140, H - 300, 700);
    for (let i = 0; i < 5; i++) { await page.keyboard.press('Tab'); await frame(); await hold(420); }
    await page.evaluate(() => document.activeElement && document.activeElement.blur());
    await frame(); await hold(300);
  },

  async comandos() {
    await click('nav a:has-text("Comandos")', { nav: true, after: 600 });
    await caption('RT-15', 'Comandos remotos com aprovação humana', 'Desligar a bomba, o gerador ou liberar todas as portas exige a aprovação de outra pessoa.');
    await hold(1500);
    await click('#device', { after: 200 });
    await page.keyboard.press('Escape');
    await page.selectOption('#device', 'escola-bomba'); await frame(); await hold(500);
    await click('#action', { after: 200 });
    await page.keyboard.press('Escape');
    await page.selectOption('#action', 'off'); await frame(); await hold(600);
    await click('form.panel button[type=submit]', { nav: true, after: 1200 });
    await caption('RT-15', 'Ação de alto impacto: aguardando aprovação', 'O pedido fica parado até a coordenação decidir — nada chega à borda antes disso.');
    await hold(1800);
    await scrollToEl('h2:has-text("Últimos comandos")', 90, 1300);
    await hover('td:has-text("aguardando aprovação")', { after: 300 });
    await caption('RT-15', 'Regra dos quatro olhos', 'Quem pediu não vê o botão “Aprovar”: outra pessoa da coordenação precisa decidir.');
    await hold(3000);
    const ap = page.locator('button[value=aprovar]');
    if (await ap.count() && false) {
      await caption('RT-15', 'Regra dos quatro olhos', 'Quem pediu não pode aprovar o próprio pedido.');
      await click(ap, { nav: true, after: 2600 });
    }
  },

  async agenda() {
    await click('nav a:has-text("Agenda da bomba")', { nav: true, after: 600 });
    await caption('RT-08', 'Agenda da bomba — validação no servidor', 'Mesma política da borda: no mínimo 2 horas de bombeamento por dia.');
    await hold(1600);
    await page.selectOption('form.panel #site', 'escola').catch(() => {});
    await fill('#windows', '03:00-03:05');
    await click('form.panel button[type=submit]', { nav: true, after: 900 });
    await caption('RT-08', 'Agenda do incidente INC-VA-0712 recusada', 'A agenda “03:00-03:05” deixaria a escola sem água — é rejeitada no painel e, de novo, na borda.');
    await hold(3000);
  },

  async soc() {
    await click('nav a:has-text("SOC")', { nav: true, after: 600 });
    await caption('RT-13 · RT-15', 'Console do SOC: respostas do SOAR', 'Baixo risco é automático (bloquear IP, revogar sessão, modo seguro); alto impacto aguarda aprovação.');
    await hold(2600);
    const det = page.locator('summary:has-text("Detalhes")');
    if (await det.count()) { await click(det, { after: 2200 }); await click(det, { after: 500 }); }
    await scrollToEl('h2:has-text("Alertas recentes")', 110, 1400);
    await caption('RT-13', 'Alertas do Wazuh correlacionados', '(a) login VPN anômalo · (b) SQL Injection · (c) dispositivo sem certificado válido · (d) comando fora do perfil.');
    await hold(2400);
    await scrollTo((await page.evaluate(() => scrollY)) + 520, 1700);
    await hold(1600);
    await scrollTo(0, 1400);
  },

  async auditoria() {
    await click('nav a:has-text("Auditoria")', { nav: true, after: 600 });
    await caption('RT-12', 'Trilha de auditoria (somente leitura)', 'Quem fez o quê, quando e de onde — inclusive o pedido de desligar a bomba e a tentativa de autoaprovação.');
    await hold(2400);
    const det = page.locator('summary:has-text("Detalhes")');
    if (await det.count()) { await click(det, { after: 2200 }); }
    await click('nav a:has-text("Segurança")', { nav: true, after: 600 });
    await caption('RT-18', 'Orientação contra golpes com IA', 'Voz clonada e e-mail urgente: confirmar fora de banda e usar a palavra-código.');
    await hold(1500);
    await scrollTo(400, 1600); await hold(1400); await scrollTo(0, 1200);
  },

  async legado() {
    await noCaption();
    await card('Cena 3 · SQL Injection — antes', 'Painel legado (vulnerável)',
      'Reprodução controlada, só no laboratório: a versão antiga monta a consulta concatenando texto e não tem MFA.', 'RT-08 · INC-VA-0712', 2600);
    await goto(LEGADO + '/login');
    await uncard();
    await caption('ANTES', 'Painel legado: somente senha', 'Credencial obtida por phishing (conta fictícia de laboratório).');
    await fill('#username', 'diego.op');
    await fill('#password', ops['diego.op'].pw, { fast: true });
    await click('form.panel button[type=submit]', { nav: true, after: 700 });
    await click('nav a:has-text("Histórico de acessos")', { nav: true, after: 500 });
    await caption('ANTES', 'Injeção no campo de busca', 'UNION SELECT extrai o cadastro sintético de pessoas.');
    await fill('#q', "x' UNION SELECT now(),nome,email,telefone,true,papel FROM cadastro.pessoas--", { fast: true });
    await click('form.filters button[type=submit]', { nav: true, after: 900 });
    await caption('ANTES', 'Vazamento: nomes, e-mails e telefones (sintéticos)', 'Exatamente o que aconteceu no INC-VA-0712.');
    await scrollToEl('table', 100, 1200);
    await hold(1400); await scrollTo(700, 1800); await hold(1200); await scrollTo(0, 1200);
  },

  async corrigido() {
    await card('Cena 4 · SQL Injection — depois', 'Painel corrigido + WAF + SOAR',
      'Consulta parametrizada, validação no servidor, usuário de banco com privilégio mínimo, erro genérico — e detecção com resposta.', 'RT-08 · RT-13 · RT-15', 2600);
    await goto(PAINEL + '/acessos');
    await uncard();
    await caption('DEPOIS', 'Busca legítima funciona normalmente', 'Registros de acesso pseudonimizados (LGPD — RT-19).');
    await fill('#q', 'fechadura');
    await click('form.filters button[type=submit]', { nav: true, after: 1600 });
    await caption('DEPOIS', 'Entrada fora do padrão é recusada pela aplicação', 'Validação no servidor com mensagem simples, sem detalhes do banco.');
    await fill('#q', 'bomba*');
    await click('form.filters button[type=submit]', { nav: true, after: 2400 });
    await caption('DEPOIS', 'Payload de SQL Injection barrado no gateway', 'O WAF devolve 403 e registra; o Wazuh gera o alerta (b) e o SOAR reage sozinho.');
    await fill('#q', "x' OR '1'='1", { fast: true });
    const t0 = Date.now();
    await click('form.filters button[type=submit]', { nav: true, after: 0 });
    await page.evaluate(() => { document.body.style.zoom = '2'; document.body.style.textAlign = 'center'; document.body.style.paddingTop = '6rem'; }).catch(() => {});
    await frame(); await hold(2600);
    // aguarda o SOAR revogar a sessão VPN deste notebook (o painel deixa de responder)
    let cut = null;
    while (Date.now() - t0 < 60000) {
      const ok = await page.request.get(PAINEL + '/healthz', { timeout: 2500 }).then(r => r.ok()).catch(() => false);
      if (!ok) { cut = Date.now() - t0; break; } await sleep(1000);
    }
    if (!cut) throw new Error('SOAR não revogou a sessão em 60 s');
    await card('RT-13 · RT-15 · resposta automática', `Sessão VPN revogada em ${Math.round(cut / 1000)} s`,
      'Do payload ao bloqueio sem intervenção humana: o Wazuh detectou o padrão (b) e o SOAR encerrou o túnel deste notebook. O painel fica inacessível até nova verificação com MFA.',
      'Tempo medido ao vivo nesta gravação', 4200);
  },

  async fim() {
    await noCaption();
    await card('Vila Aurora · resumo', 'Segura por padrão, resiliente e investigável',
      'mTLS e PKI própria · WireGuard + MFA · RBAC · SQLi corrigido na causa raiz · Wazuh + SOAR com aprovação humana · forense do INC-VA-0712.',
      'Código, evidências e laudos no repositório do projeto', 4200);
  },
};

(async () => {
  const browser = await chromium.launch({
    proxy: { server: 'socks5://127.0.0.1:1080', bypass: '172.30.30.80,localhost,127.0.0.1' },
    args: ['--font-render-hinting=none', '--disable-lcd-text'],
  });
  const ctx = await browser.newContext({ viewport: { width: W, height: H }, deviceScaleFactor: DSF, ignoreHTTPSErrors: true,
    bypassCSP: true, locale: 'pt-BR', timezoneId: 'America/Sao_Paulo', colorScheme: 'light', reducedMotion: 'reduce' });
  await ctx.addInitScript(OVERLAY);
  page = await ctx.newPage();
  page.setDefaultTimeout(15000);
  const order = Object.keys(SCENES).filter(k => !ONLY || ONLY.includes(k));
  try {
    for (const k of order) { const t = frames; await SCENES[k](); console.log(`cena ${k}: ${((frames - t) / FPS).toFixed(1)}s`); }
  } catch (e) { console.error('ERRO', e); await page.screenshot({ path: OUT + '.erro.png' }).catch(() => {}); }
  finally {
    ff.stdin.end(); await new Promise(r => ff.on('close', r));
    await browser.close();
    console.log(`total ${(frames / FPS).toFixed(1)}s -> ${OUT}`);
  }
})();
