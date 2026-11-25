"use strict";
// Read-only monitor. Downloads the encrypted snapshot the server publishes every minute and decrypts it here.
// The derived key stays on this device as a non-extractable CryptoKey until "Salir"; nothing is ever sent anywhere.
const REPO = "maximodecimob/ops-monitor";
const LOCAL = location.hostname === "localhost" || location.hostname === "127.0.0.1";
const SOURCES = LOCAL ? ["snap.json"] : [
  `https://api.github.com/repos/${REPO}/contents/snap.json?ref=data`, // fresh (60 req/h per IP)
  `https://raw.githubusercontent.com/${REPO}/data/snap.json`,          // fallback (cached up to 5 min)
];
const POLL_MS = 75_000, STALE_MS = 3 * 60_000;
const AAD = new TextEncoder().encode("ops-monitor-v1");
const $ = (id) => document.getElementById(id);
let key = null, salt = null, snap = null, range = 7, timer = null;

if (top !== self) throw new Error("framed");

// ---------- storage: one IndexedDB record {key, salt} ----------
function db() {
  return new Promise((ok, ko) => {
    const r = indexedDB.open("monitor", 1);
    r.onupgradeneeded = () => r.result.createObjectStore("k");
    r.onsuccess = () => ok(r.result); r.onerror = () => ko(r.error);
  });
}
async function store(mode, fn) {
  const d = await db();
  return new Promise((ok, ko) => {
    const req = fn(d.transaction("k", mode).objectStore("k"));
    req.onsuccess = () => ok(req.result); req.onerror = () => ko(req.error);
  });
}

// ---------- fetch + decrypt ----------
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
async function download() {
  for (const url of SOURCES) {
    try {
      const r = await fetch(url, { cache: "no-store", credentials: "omit", referrerPolicy: "no-referrer",
                                   headers: url.includes("api.github") ? { Accept: "application/vnd.github.raw" } : {} });
      if (r.ok) return await r.json();
    } catch { /* next source */ }
  }
  throw new Error("No se pudo descargar el snapshot");
}
async function derive(pass, s, iter) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pass), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: b64(s), iterations: iter },
                                 base, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
}
async function open(env, k) {
  if (env.v !== 1) throw new Error("Formato desconocido");
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64(env.iv), additionalData: AAD }, k, b64(env.ct));
  const text = await new Response(new Blob([plain]).stream().pipeThrough(new DecompressionStream("deflate"))).text();
  return JSON.parse(text);
}

// ---------- flow ----------
async function refresh() {
  try {
    const env = await download();
    if (env.salt !== salt) return lock("La contraseña del monitor ha cambiado. Vuelve a entrar.");
    snap = await open(env, key);
    render();
  } catch (e) {
    if (e.name === "OperationError") return lock("No se pudo descifrar. Vuelve a entrar.");
    banner(e.message);
  }
}
function schedule() {
  clearInterval(timer);
  timer = setInterval(() => { if (!document.hidden) refresh(); }, POLL_MS);
}
function lock(msg) {
  clearInterval(timer); key = snap = null;
  store("readwrite", (s) => s.clear()).catch(() => {});
  $("app").hidden = true; $("lock").hidden = false; $("lockmsg").textContent = msg || "";
  $("pass").value = ""; $("pass").focus();
}
async function unlock(ev) {
  ev.preventDefault();
  const btn = ev.submitter; btn.disabled = true; $("lockmsg").textContent = "Comprobando…";
  try {
    const env = await download();
    const k = await derive($("pass").value, env.salt, env.iter);
    snap = await open(env, k);
    key = k; salt = env.salt;
    await store("readwrite", (s) => s.put({ key, salt }, "k"));
    show();
  } catch (e) {
    $("lockmsg").textContent = e.name === "OperationError" ? "Contraseña incorrecta" : e.message;
  } finally { btn.disabled = false; $("pass").value = ""; }
}
function show() { $("lock").hidden = true; $("app").hidden = false; render(); schedule(); }

document.addEventListener("visibilitychange", () => { if (!document.hidden && key) refresh(); });
$("unlock").addEventListener("submit", unlock);
$("logout").addEventListener("click", () => lock(""));
store("readonly", (s) => s.get("k")).then((rec) => {
  if (!rec) return lock("");
  key = rec.key; salt = rec.salt; $("app").hidden = false; refresh(); schedule();
}).catch(() => lock(""));

// ---------- rendering (DOM nodes + textContent only) ----------
function h(tag, attrs, ...kids) {
  const el = tag.startsWith("svg:") ? document.createElementNS("http://www.w3.org/2000/svg", tag.slice(4))
                                    : document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "style") el.style.cssText = v; // CSSOM: allowed by the CSP, unlike a style attribute
    else if (k === "class") el.setAttribute("class", v); else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null && c !== false) el.append(c instanceof Node ? c : String(c));
  return el;
}
const money = (v) => v == null ? "—" : v.toLocaleString("es-ES", { style: "currency", currency: "USD", maximumFractionDigits: 2 });
const pct = (v, d = 2) => v == null ? "—" : `${v >= 0 ? "+" : ""}${(v * 100).toFixed(d)} %`;
const signed = (v) => h("span", { class: `num ${v > 0 ? "up" : v < 0 ? "down" : ""}` }, v > 0 ? "+" : "", money(v));
const ago = (ms) => { const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  return s < 90 ? `hace ${s} s` : s < 5400 ? `hace ${Math.round(s / 60)} min` : `hace ${Math.round(s / 3600)} h`; };
const PERIODS = [["today", "Hoy"], ["week", "Semana"], ["month", "Mes"], ["ytd", "Año"], ["all", "Total"]];
const STATE = { ACTIVE: ["Activo", "s-ok"], REDUCING: ["Reduciendo", "s-warn"], HALTED: ["Detenido", "s-crit"] };
const HEALTH = { GREEN: ["Bien", "s-ok"], AMBER: ["Vigilar", "s-warn"], RED: ["Mal", "s-crit"] };
const status = (map, v) => { const [t, c] = map[v] || [v || "—", ""]; return h("span", { class: `status ${c}` }, t); };

function banner(msg) { $("stale").hidden = !msg; $("stale").textContent = msg || ""; }

function render() {
  if (!snap) return;
  $("age").textContent = `Actualizado ${ago(snap.ts_ms)}`;
  banner(Date.now() - snap.ts_ms > STALE_MS ? `Datos sin actualizar desde ${ago(snap.ts_ms)}: el servidor no publica.` : "");
  $("total").replaceChildren(h("span", { class: "muted" }, "Capital total"),
    h("div", { class: "hero num" }, money(snap.total.equity)), periods(snap.total.periods));
  const s = snap.system || {};
  const meter = (label, used, total, fmt) => used == null || !total
    ? h("div", { class: "meter" }, h("span", null, label), h("b", null, "—"))
    : h("div", { class: "meter" }, h("span", null, label), h("b", { class: "num" }, `${fmt(used)} / ${fmt(total)}`),
      h("div", { class: "bar" }, h("i", { class: used / total > 0.85 ? "hi" : "",
        style: `width:${Math.min(100, used / total * 100).toFixed(0)}%` })));
  const gb = (b) => b >= 1e12 ? `${(b / 1e12).toFixed(2)} TB` : `${(b / 1e9).toFixed(1)} GB`;
  const cores = (c) => `${c.toFixed(c % 1 ? 2 : 0)} núcleos`;
  $("system").replaceChildren(h("h2", null, "Servidor"), h("div", { class: "meters", style: "margin-top:10px" },
    meter("CPU", s.cpu_cores_used, s.cpu_cores, cores),
    meter("Memoria", s.mem_used_b, s.mem_total_b, gb),
    meter("Disco", s.disk_used_b, s.disk_total_b, gb),
    h("div", { class: "meter" }, h("span", null, "Encendido"), h("b", { class: "num" }, `${(s.uptime_s / 86400).toFixed(1)} días`))));
  $("accounts").replaceChildren(...snap.accounts.map(account));
}

function periods(p) {
  return h("div", { class: "periods" }, PERIODS.map(([k, label]) => h("div", null, h("span", { class: "muted" }, label),
    p?.[k] ? [h("b", null, signed(p[k].pnl)), h("span", { class: "num muted" }, pct(p[k].return))] : h("b", null, "—"))));
}

function account(a) {
  const t = a.telemetry;
  const head = h("div", { class: "row" }, h("h2", null, a.name),
    h("span", { class: `tag ${a.mode === "live" ? "live" : ""}` }, a.mode === "live" ? "REAL" : "PAPER"));
  if (!t) return h("section", { class: "card" }, head, h("p", { class: "empty" }, "Motor parado: sin datos en vivo."),
                   periods(a.periods), chart(a.curve));
  const dd = t.day_drawdown_limit ? Math.min(1, Math.abs(t.day_drawdown) / Math.abs(t.day_drawdown_limit)) : 0;
  const brokers = (t.brokers || []).map((b) => h("span", { class: `status ${b.connected ? "s-ok" : "s-crit"}` },
    `${b.id || b.type} ${b.connected ? "conectado" : "desconectado"}`));
  return h("section", { class: "card" }, head,
    h("div", { class: "row muted", style: "margin:4px 0 8px" }, status(STATE, t.state),
      t.bundle_name ? h("span", null, t.bundle_name, " · ", status(HEALTH, t.bundle_health)) : null, ...brokers),
    t.halt_reason ? h("p", { class: "banner" }, `Motivo de parada: ${t.halt_reason}`) : null,
    h("div", { class: "hero num" }, money(a.equity)), periods(a.periods), chart(a.curve),
    h("h3", null, "Riesgo"),
    h("div", { class: "meters" },
      h("div", { class: "meter" }, h("span", null, "Pérdida del día / límite"),
        h("b", { class: "num" }, `${(t.day_drawdown * 100).toFixed(2)} % de ${(t.day_drawdown_limit * 100).toFixed(2)} %`),
        h("div", { class: "bar" }, h("i", { class: dd > 0.7 ? "hi" : "", style: `width:${(dd * 100).toFixed(0)}%` }))),
      h("div", { class: "meter" }, h("span", null, "Apalancamiento bruto"), h("b", { class: "num" }, `${t.gross.toFixed(2)}x`)),
      h("div", { class: "meter" }, h("span", null, "Apalancamiento neto"), h("b", { class: "num" }, `${t.net.toFixed(2)}x`))),
    h("h3", null, "Estrategias"), table(["Estrategia", "Salud", "Ops cerradas", "P&L", "Rent."], t.strategies,
      (s) => [s.name, status(HEALTH, s.health), s.trades, signed(s.pnl), pct(s.return_pct)]),
    h("h3", null, "Posiciones abiertas"), table(["Instrumento", "Estrategia", "Nocional", "P&L no real."], t.positions,
      (p) => [p.instrument, p.strategy, money(p.signed_notional), signed(p.unrealized_pnl)]),
    t.flows?.length ? [h("h3", null, "Depósitos y retiros"), table(["Fecha", "Importe"], t.flows,
      (f) => [new Date(f.ts_ms).toLocaleString("es-ES"), signed(f.amount)])] : null);
}

function table(cols, rows, cells) {
  if (!rows?.length) return h("p", { class: "empty" }, "Ninguna");
  const r = (i) => (i >= 2 ? "r" : "");
  return h("table", null, h("thead", null, h("tr", null, cols.map((c, i) => h("th", { class: r(i) }, c)))),
    h("tbody", null, rows.map((row) => h("tr", null, cells(row).map((c, i) => h("td", { class: `${r(i)} num` }, c))))));
}

// Single-series line: capital net of deposits/withdrawals (curve rows = [ts_ms, equity, cumulative flow]).
function chart(curve) {
  const wrap = h("div", { class: "chart" });
  const draw = () => {
    const since = Date.now() - range * 86_400_000;
    const pts = (curve || []).filter((c) => c[0] >= since).map((c) => [c[0], c[1] - c[2]]);
    const btns = h("div", { class: "range" }, [1, 7, 30].map((d) => h("button", { type: "button",
      "aria-pressed": String(d === range), onclick: () => { range = d; render(); } }, d === 1 ? "24 h" : `${d} d`)));
    if (pts.length < 2) return wrap.replaceChildren(btns, h("p", { class: "empty" }, "Sin historial en este periodo"));
    const W = 600, H = 160, P = 6;
    const xs = pts.map((p) => p[0]), ys = pts.map((p) => p[1]);
    const x0 = Math.min(...xs), x1 = Math.max(...xs), y0 = Math.min(...ys), y1 = Math.max(...ys);
    const X = (v) => P + ((v - x0) / (x1 - x0 || 1)) * (W - 2 * P);
    const Y = (v) => H - P - ((v - y0) / (y1 - y0 || 1)) * (H - 2 * P);
    const d = pts.map((p, i) => `${i ? "L" : "M"}${X(p[0]).toFixed(1)},${Y(p[1]).toFixed(1)}`).join("");
    const dot = h("svg:circle", { r: "4", fill: "var(--series)", stroke: "var(--surface)", "stroke-width": "2", visibility: "hidden" });
    const cross = h("svg:line", { y1: "0", y2: String(H), stroke: "var(--line)", visibility: "hidden" });
    const tip = h("div", { class: "tip", hidden: "" });
    const svg = h("svg:svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img",
      "aria-label": `Capital de ${money(ys[0])} a ${money(ys[ys.length - 1])}` },
      h("svg:line", { x1: "0", x2: String(W), y1: String(H - 0.5), y2: String(H - 0.5), stroke: "var(--line)" }),
      cross, h("svg:path", { d, fill: "none", stroke: "var(--series)", "stroke-width": "2", "vector-effect": "non-scaling-stroke",
        "stroke-linejoin": "round" }), dot);
    const move = (ev) => {
      const box = svg.getBoundingClientRect(), fx = ((ev.clientX - box.left) / box.width) * W;
      let i = 0; for (let j = 1; j < pts.length; j++) if (Math.abs(X(pts[j][0]) - fx) < Math.abs(X(pts[i][0]) - fx)) i = j;
      const [tx, ty] = [X(pts[i][0]), Y(pts[i][1])];
      dot.setAttribute("cx", tx); dot.setAttribute("cy", ty); cross.setAttribute("x1", tx); cross.setAttribute("x2", tx);
      dot.setAttribute("visibility", "visible"); cross.setAttribute("visibility", "visible");
      tip.hidden = false; tip.style.left = `${Math.min(Math.max((tx / W) * 100, 15), 85)}%`;
      tip.textContent = `${new Date(pts[i][0]).toLocaleString("es-ES", { dateStyle: "short", timeStyle: "short" })} · ${money(pts[i][1])}`;
    };
    const leave = () => { tip.hidden = true; dot.setAttribute("visibility", "hidden"); cross.setAttribute("visibility", "hidden"); };
    svg.addEventListener("pointermove", move); svg.addEventListener("pointerdown", move); svg.addEventListener("pointerleave", leave);
    const chg = ys[ys.length - 1] - ys[0];
    wrap.replaceChildren(h("div", { class: "row" }, h("span", { class: "muted" }, "Capital neto de depósitos ", signed(chg)), btns), svg, tip);
  };
  draw();
  return wrap;
}
