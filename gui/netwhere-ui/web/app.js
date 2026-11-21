"use strict";
// netwhere window. Data comes from MoonBit (api.mbt) over WebView messages;
// this file only lays it out. Byte counts are formatted like the CLI.

// ---------- bridge ----------

const pending = new Map();
let nextId = 1;

function call(q, arg) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    window.moonview.postMessage(JSON.stringify({ id, q, arg: arg || {} }));
  });
}

window.moonview.onmessage = (ev) => {
  let m;
  try { m = JSON.parse(ev.data); } catch (_) { return; }
  const p = pending.get(m.id);
  if (!p) return;
  pending.delete(m.id);
  if ("err" in m) p.reject(new Error(m.err)); else p.resolve(m.ok);
};

// ---------- formatting ----------

const UNITS = ["B", "KB", "MB", "GB", "TB"];

// Same as report.human_bytes.
function bytes(n) {
  if (n < 1024) return n + " B";
  let v = n, u = 0;
  while (v >= 1024 && u < UNITS.length - 1) { v /= 1024; u++; }
  const tenths = Math.floor(v * 10 + 0.5);
  return Math.floor(tenths / 10) + "." + (tenths % 10) + " " + UNITS[u];
}

function pct(part, total) {
  if (!total) return "0%";
  const p = part * 100 / total;
  return (p > 0 && p < 0.1 ? "<0.1" : p.toFixed(p < 10 ? 1 : 0)) + "%";
}

function duration(s) {
  if (s < 60) return s + " 秒";
  if (s < 3600) return Math.round(s / 60) + " 分钟";
  const h = Math.floor(s / 3600), m = Math.round((s % 3600) / 60);
  return h + " 小时" + (m ? " " + m + " 分" : "");
}

function esc(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}

const ROUTES = [
  { name: "经节点", help: "进入代理内核，从代理节点出去" },
  { name: "内核直连", help: "进入代理内核，按规则直连（DIRECT）或拒绝（REJECT）" },
  { name: "出口未知", help: "进入了代理内核，但没有关联到内核记录，或多条记录出口不一致；不计入任何节点" },
  { name: "绕过 / 直连", help: "没有进入代理内核：有内核时是绕过，没有内核时是直连" },
  { name: "局域网", help: "目的地在局域网" },
];

const PERIOD_NAMES = { today: "今天", "24h": "最近 24 小时", "7d": "最近 7 天", "30d": "最近 30 天" };
const BY_NAMES = { app: "应用", domain: "域名", process: "进程", node: "节点", entry: "入口" };
const ENTRY_NAMES = { "proxy-port": "代理端口", tun: "TUN", bypass: "绕过", direct: "直连", lan: "局域网" };
const NEXT_BY = { app: "domain", domain: "process", process: "domain", node: "app", entry: "app" };

const sum = (a) => a.reduce((x, y) => x + y, 0);

function keyLabel(by, key) {
  if (by === "entry") return ENTRY_NAMES[key] || key;
  return key;
}

// ---------- shared UI bits ----------

const $ = (sel) => document.querySelector(sel);
const page = $("#page");
let toastTimer = 0;

function toast(text, isErr) {
  const t = $("#toast");
  t.textContent = text;
  t.className = "toast" + (isErr ? " err" : "");
  t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, isErr ? 6000 : 3500);
}

function fail(e) { toast(e.message || String(e), true); }

function shareBar(split, cls) {
  const total = sum(split);
  if (!total) return `<div class="${cls}"></div>`;
  return `<div class="${cls}">` + split.map((v, i) =>
    v > 0 ? `<span class="c${i}" style="flex:${v} 1 0"></span>` : "").join("") + "</div>";
}

function legendKey() {
  return `<div class="keyrow">` + ROUTES.map((r, i) =>
    `<span title="${esc(r.help)}"><i class="chip c${i}"></i>${r.name}</span>`).join("") + "</div>";
}

function numCell(v) {
  return v ? `<td class="n">${bytes(v)}</td>` : `<td class="n zero">–</td>`;
}

// Tooltip near the pointer.
const tip = $("#tip");
function showTip(html, x, y) {
  tip.innerHTML = html;
  tip.hidden = false;
  const r = tip.getBoundingClientRect();
  let left = x + 14, top = y + 14;
  if (left + r.width > innerWidth - 8) left = x - r.width - 14;
  if (top + r.height > innerHeight - 8) top = y - r.height - 14;
  tip.style.left = Math.max(8, left) + "px";
  tip.style.top = Math.max(8, top) + "px";
}
function hideTip() { tip.hidden = true; }

// ---------- trend chart (stacked columns, one y axis) ----------

function niceStep(max, ticks) {
  // Byte-friendly steps: 1, 2, 5 × 1024^k scaled within the unit.
  let unit = 1;
  while (max / unit >= 1024 && unit < 1024 ** 4) unit *= 1024;
  const raw = max / unit / ticks;
  const mag = Math.pow(10, Math.floor(Math.log10(raw || 1)));
  const f = raw / mag;
  const nice = f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10;
  return nice * mag * unit;
}

function axisLabel(v) {
  if (v === 0) return "0";
  let u = 0;
  while (v >= 1024 && u < UNITS.length - 1) { v /= 1024; u++; }
  return (Number.isInteger(v) ? v : v.toFixed(1)) + " " + UNITS[u];
}

function timeLabel(text, interval) {
  // text: "YYYY-MM-DD HH:MM", local time
  if (interval >= 1440) return text.slice(5, 10);
  if (text.slice(11, 16) === "00:00") return text.slice(5, 10);
  return text.slice(11, 16);
}

// Minutes since the epoch in local time, from "YYYY-MM-DD HH:MM".
function localMinutes(text) {
  const d = new Date(text.replace(" ", "T") + ":00");
  return Math.round(d.getTime() / 60000) - d.getTimezoneOffset();
}

function drawTrend(el, tl, step) {
  const W = el.clientWidth, H = el.clientHeight;
  const padL = 64, padR = 8, padT = 8, padB = 24;
  const n = tl.length;
  if (!n || W < 50) { el.innerHTML = ""; return; }
  const totals = tl.map((b) => sum(b[1]));
  const max = Math.max(...totals, 1);
  const stepY = niceStep(max, 4);
  const top = Math.ceil(max / stepY) * stepY;
  const plotW = W - padL - padR, plotH = H - padT - padB;
  const slot = plotW / n;
  const barW = Math.max(1, Math.min(28, slot * 0.72));
  const y = (v) => padT + plotH - (v / top) * plotH;
  let s = "";
  for (let v = 0; v <= top + 1e-9; v += stepY) {
    const yy = Math.round(y(v)) + 0.5;
    s += `<line class="${v === 0 ? "baseline" : "gridline"}" x1="${padL}" x2="${W - padR}" y1="${yy}" y2="${yy}"/>`;
    s += `<text x="${padL - 8}" y="${yy + 4}" text-anchor="end">${axisLabel(v)}</text>`;
  }
  // Labels on round times (whole hours, days), as many as fit.
  const fit = Math.max(2, Math.floor(plotW / 70));
  const intervals = [15, 30, 60, 120, 180, 240, 360, 720, 1440, 2880, 4320, 10080];
  const interval = intervals.find((m) => m >= step && (n * step) / m <= fit) || 10080;
  for (let i = 0; i < n; i++) {
    if (localMinutes(tl[i][0]) % interval !== 0) continue;
    const cx = padL + slot * (i + 0.5);
    s += `<text x="${cx}" y="${H - 6}" text-anchor="middle">${esc(timeLabel(tl[i][0], interval))}</text>`;
  }
  s += `<rect id="hov" class="hover" x="0" y="${padT}" width="${slot}" height="${plotH}" visibility="hidden"/>`;
  for (let i = 0; i < n; i++) {
    const segs = tl[i][1];
    const x = padL + slot * i + (slot - barW) / 2;
    let acc = 0;
    const last = segs.reduce((k, v, j) => (v > 0 ? j : k), -1);
    segs.forEach((v, j) => {
      if (v <= 0) return;
      const y0 = y(acc), y1 = y(acc + v);
      acc += v;
      // 2 px surface gap between stacked segments (none below the first).
      const gap = acc - v > 0 ? 2 : 0;
      const h = Math.max(0, y0 - y1 - gap);
      if (h <= 0) return;
      if (j === last) {
        const r = Math.min(4, barW / 2, h);
        s += `<path class="s${j}" d="M${x},${y0 - gap}V${y1 + r}Q${x},${y1} ${x + r},${y1}H${x + barW - r}Q${x + barW},${y1} ${x + barW},${y1 + r}V${y0 - gap}Z"/>`;
      } else {
        s += `<rect class="s${j}" x="${x}" y="${y1}" width="${barW}" height="${h}"/>`;
      }
    });
  }
  el.innerHTML = `<svg viewBox="0 0 ${W} ${H}" role="img" aria-label="流量趋势">${s}</svg>`;
  const svg = el.firstChild, hov = svg.querySelector("#hov");
  svg.addEventListener("mousemove", (e) => {
    const r = svg.getBoundingClientRect();
    const i = Math.floor((e.clientX - r.left - padL) / slot);
    if (i < 0 || i >= n) { hov.setAttribute("visibility", "hidden"); hideTip(); return; }
    hov.setAttribute("x", padL + slot * i);
    hov.setAttribute("visibility", "visible");
    const segs = tl[i][1], tot = sum(segs);
    const end = tl[i + 1] ? tl[i + 1][0] : null;
    let h = `<div class="t">${esc(tl[i][0].slice(5))}${end ? " – " + esc(end.slice(11)) : ""}</div>`;
    ROUTES.forEach((rt, j) => {
      if (segs[j] > 0) h += `<div class="r"><i class="chip c${j}"></i>${rt.name}<b>${bytes(segs[j])}</b></div>`;
    });
    h += `<div class="r">合计<b>${bytes(tot)}</b></div>`;
    showTip(h, e.clientX, e.clientY);
  });
  svg.addEventListener("mouseleave", () => { hov.setAttribute("visibility", "hidden"); hideTip(); });
}

// ---------- state ----------

const state = {
  page: "overview",
  period: "today",
  status: null,
  detail: { by: "app", filters: [], search: "", sort: null },
};

const PAGES = {
  overview: { title: "概览", period: true, render: renderOverview },
  detail: { title: "明细", period: true, render: renderDetail },
  nodes: { title: "节点与套餐", period: true, render: renderNodes },
  unknown: { title: "待归类", period: true, render: renderUnknown },
  rules: { title: "规则", period: false, render: renderRules },
  settings: { title: "设置", period: false, render: renderSettings },
};

let renderSeq = 0;

function go(name) {
  if (!PAGES[name]) name = "overview";
  state.page = name;
  document.querySelectorAll("#nav a").forEach((a) => a.classList.toggle("on", a.dataset.page === name));
  $("#title").textContent = PAGES[name].title;
  $("#period").hidden = !PAGES[name].period;
  hideTip();
  render();
}

async function render() {
  const seq = ++renderSeq;
  try {
    await PAGES[state.page].render(() => seq === renderSeq);
  } catch (e) {
    if (seq === renderSeq) page.innerHTML = `<div class="card"><div class="empty">${esc(e.message)}</div></div>`;
  }
}

window.addEventListener("hashchange", () => go(location.hash.slice(1)));
document.querySelectorAll("#period button").forEach((b) => b.addEventListener("click", () => {
  state.period = b.dataset.period;
  document.querySelectorAll("#period button").forEach((x) => x.classList.toggle("on", x === b));
  render();
}));

// ---------- status ----------

const PHASE_TEXT = { running: "运行中", paused: "已暂停", stopped: "已停止", "not-installed": "未安装" };

async function refreshStatus() {
  try {
    const st = await call("status");
    state.status = st;
    const pill = $("#state-pill");
    pill.className = "pill " + st.phase;
    pill.querySelector(".pill-text").textContent = "采集" + PHASE_TEXT[st.phase] + (st.phase === "running" && st.degraded ? "（降级）" : "");
    const act = $("#state-action");
    const label = { running: "暂停", paused: "恢复", stopped: "启动" }[st.phase];
    act.hidden = !label;
    act.textContent = label ? label + "采集" : "";
    const b = $("#banner");
    if (st.phase === "not-installed") {
      b.textContent = "采集进程还没有安装。在终端运行 netwhere install（会弹出一次 UAC 确认）。";
      b.hidden = false;
    } else if (st.phase === "stopped") {
      b.textContent = "采集已停止：这段时间的流量不会记录。可以在左下角启动。";
      b.hidden = false;
    } else if (st.phase === "running" && st.degraded) {
      b.textContent = "采集进程没有管理员权限，直连流量记录不完整（只有 DNS 和代理内核的数据）。";
      b.hidden = false;
    } else {
      b.hidden = true;
    }
  } catch (_) { /* keep the last state */ }
}

$("#state-action").addEventListener("click", async () => {
  const action = { running: "pause", paused: "resume", stopped: "start" }[state.status && state.status.phase];
  if (!action) return;
  try {
    await call("control", { action });
    toast({ pause: "已请求暂停", resume: "已请求恢复", start: "正在启动采集" }[action]);
    setTimeout(refreshStatus, 1500);
    setTimeout(refreshStatus, 6000);
  } catch (e) { fail(e); }
});

// ---------- overview ----------

function coverageNote(c) {
  if (c.none) return "这段时间没有覆盖记录，无法排除缺口。";
  const parts = [];
  if (c.collector < c.span) parts.push(`采集进程只运行了 ${duration(c.collector)}（共 ${duration(c.span)}），其余时间的流量没有记录`);
  if (c.link < c.core) parts.push(`代理内核的连接流断开了 ${duration(c.core - c.link)}，期间进入内核的流量出口未知`);
  if (c.etw_lost > 0 || c.dropped > 0) parts.push(`丢失事件：ETW ${c.etw_lost} 个，队列 ${c.dropped} 个；字节数是下限`);
  return parts.join("；");
}

async function renderOverview(current) {
  const d = await call("overview", { period: state.period });
  if (!current()) return;
  const t = d.total;
  const plan = d.plan_uncertain > 0
    ? `${bytes(d.plan_low)} – ${bytes(d.plan_high)}`
    : bytes(d.plan_low);
  const cov = coverageNote(d.coverage);
  let h = `<div class="grid tiles">
    <div class="card tile"><div class="label">总流量 · ${PERIOD_NAMES[state.period]}</div>
      <div class="value">${bytes(t)}</div><div class="sub">↓ ${bytes(d.down)} · ↑ ${bytes(d.up)}</div></div>
    <div class="card tile" title="节点流量 × 倍率；不含代理协议开销"><div class="label">套餐消耗估算</div>
      <div class="value">${plan}</div><div class="sub">${d.plan_uncertain > 0 ? `其中 ${bytes(d.plan_uncertain)} 出口未知或有歧义，按最大倍率计入上限` : "按节点倍率计算"}</div></div>
    <div class="card tile"><div class="label">经过代理内核</div>
      <div class="value">${pct(d.split[0] + d.split[1] + d.split[2], t)}</div>
      <div class="sub">绕过 / 直连 ${bytes(d.split[3])}</div></div>
  </div>`;
  h += `<div class="card"><h2>流量走向</h2>${shareBar(d.split, "share")}<div class="legend">` +
    ROUTES.map((r, i) => `<div class="item" title="${esc(r.help)}"><i class="chip c${i}"></i><div>
      <div class="name">${r.name}</div><div><span class="num">${bytes(d.split[i])}</span><span class="pct">${pct(d.split[i], t)}</span></div></div></div>`).join("") +
    `</div>${cov ? `<div class="warnline">${esc(cov)}</div>` : ""}</div>`;
  h += `<div class="card"><h2>趋势<span class="spacer"></span><button class="link small" id="tl-table">显示数据</button></h2>
    ${legendKey()}<div class="chart" id="trend"></div><div id="tl-data" hidden></div></div>`;
  h += `<div class="card"><h2>应用<span class="spacer"></span>${d.apps_count > d.apps.length ? `<a class="link small" href="#detail">全部 ${d.apps_count} 个</a>` : ""}</h2>`;
  if (!d.apps.length) {
    h += `<div class="empty">这段时间没有记录到流量</div>`;
  } else {
    h += `<table><thead><tr><th>应用</th><th></th><th class="n">经节点</th><th class="n">绕过 / 直连</th><th class="n">合计</th></tr></thead><tbody>` +
      d.apps.map((a) => `<tr class="click" data-app="${esc(a.key)}"><td class="key">${esc(a.key)}</td>
        <td class="barcell">${shareBar(a.split, "minibar")}</td>${numCell(a.split[0])}${numCell(a.split[3])}
        <td class="n">${bytes(sum(a.split))}</td></tr>`).join("") + "</tbody></table>";
  }
  h += "</div>";
  page.innerHTML = h;
  const trend = $("#trend");
  const draw = () => drawTrend(trend, d.timeline, d.step);
  draw();
  new ResizeObserver(draw).observe(trend);
  $("#tl-table").addEventListener("click", (e) => {
    const box = $("#tl-data");
    box.hidden = !box.hidden;
    e.target.textContent = box.hidden ? "显示数据" : "隐藏数据";
    if (!box.hidden && !box.innerHTML) {
      const rows = d.timeline.filter((b) => sum(b[1]) > 0);
      box.innerHTML = rows.length ? `<table><thead><tr><th>时间</th>${ROUTES.map((r) => `<th class="n">${r.name}</th>`).join("")}<th class="n">合计</th></tr></thead><tbody>` +
        rows.map((b) => `<tr><td>${esc(b[0].slice(5))}</td>${b[1].map(numCell).join("")}<td class="n">${bytes(sum(b[1]))}</td></tr>`).join("") +
        "</tbody></table>" : `<div class="empty">没有数据</div>`;
    }
  });
  page.querySelectorAll("tr[data-app]").forEach((tr) => tr.addEventListener("click", () => {
    state.detail = { by: "domain", filters: [["app", tr.dataset.app]], search: "", sort: null };
    location.hash = "#detail";
  }));
}

// ---------- detail ----------

async function renderDetail(current) {
  const dt = state.detail;
  const d = await call("groups", { period: state.period, by: dt.by, filters: dt.filters });
  if (!current()) return;
  let rows = d.rows.map((r) => ({ key: r.key, split: r.split, total: sum(r.split) }));
  const draw = () => {
    const q = dt.search.trim().toLowerCase();
    let shown = q ? rows.filter((r) => keyLabel(dt.by, r.key).toLowerCase().includes(q)) : rows.slice();
    if (dt.sort !== null) shown.sort((a, b) => (dt.sort === 5 ? b.total - a.total : b.split[dt.sort] - a.split[dt.sort]));
    const max = Math.max(1, ...shown.map((r) => r.total));
    const body = shown.map((r) => `<tr class="click" data-key="${esc(r.key)}">
      <td class="key" title="${esc(r.key)}">${esc(keyLabel(dt.by, r.key))}</td>
      <td class="barcell"><div style="width:${Math.max(2, (r.total / max) * 100)}%">${shareBar(r.split, "minibar")}</div></td>
      ${r.split.map(numCell).join("")}<td class="n">${bytes(r.total)}</td></tr>`).join("");
    $("#detail-body").innerHTML = body || `<tr><td colspan="8" class="empty">${q ? "没有匹配的项" : "这段时间没有记录到流量"}</td></tr>`;
    $("#detail-body").querySelectorAll("tr[data-key]").forEach((tr) => tr.addEventListener("click", () => {
      dt.filters = dt.filters.concat([[dt.by, tr.dataset.key]]);
      const used = new Set(dt.filters.map((f) => f[0]));
      let next = NEXT_BY[dt.by];
      if (used.has(next)) next = ["domain", "process", "app", "node", "entry"].find((b) => !used.has(b)) || dt.by;
      dt.by = next;
      dt.search = "";
      dt.sort = null;
      render();
    }));
  };
  const crumbs = [`<button data-i="0">全部</button>`].concat(dt.filters.map((f, i) =>
    `› <button data-i="${i + 1}">${BY_NAMES[f[0]]}：${esc(keyLabel(f[0], f[1]))}</button>`)).join(" ");
  page.innerHTML = `<div class="card scroll">
    <div class="toolbar">
      <div class="seg" id="by">${Object.keys(BY_NAMES).map((b) => `<button data-by="${b}" class="${b === dt.by ? "on" : ""}">${BY_NAMES[b]}</button>`).join("")}</div>
      <div class="crumbs">${crumbs}</div>
      <span class="spacer" style="flex:1"></span>
      <input type="text" id="search" placeholder="筛选${BY_NAMES[dt.by]}" value="${esc(dt.search)}">
    </div>
    ${legendKey()}
    <div class="note" style="margin:6px 0 4px">${d.count} 个${BY_NAMES[dt.by]}${d.count > d.rows.length ? `，显示前 ${d.rows.length} 个` : ""}；点一行继续细分${dt.by === "node" ? "；只含经节点的流量" : ""}</div>
    <table><thead><tr><th>${BY_NAMES[dt.by]}</th><th></th>
      ${ROUTES.map((r, i) => `<th class="n sortable" data-sort="${i}" title="${esc(r.help)}">${r.name}</th>`).join("")}
      <th class="n sortable" data-sort="5">合计</th></tr></thead><tbody id="detail-body"></tbody></table>
  </div>`;
  draw();
  page.querySelectorAll("#by button").forEach((b) => b.addEventListener("click", () => {
    dt.by = b.dataset.by; dt.search = ""; dt.sort = null; render();
  }));
  page.querySelectorAll(".crumbs button").forEach((b) => b.addEventListener("click", () => {
    dt.filters = dt.filters.slice(0, Number(b.dataset.i)); dt.sort = null; render();
  }));
  page.querySelectorAll("th[data-sort]").forEach((th) => th.addEventListener("click", () => {
    dt.sort = Number(th.dataset.sort); draw();
  }));
  $("#search").addEventListener("input", (e) => { dt.search = e.target.value; draw(); });
}

// ---------- nodes ----------

async function renderNodes(current) {
  const [d, s] = await Promise.all([call("nodes", { period: state.period }), call("settings")]);
  if (!current()) return;
  const plan = d.plan_uncertain > 0 ? `${bytes(d.plan_low)} – ${bytes(d.plan_high)}` : bytes(d.plan_low);
  let h = `<div class="grid tiles"><div class="card tile"><div class="label">套餐消耗估算 · ${PERIOD_NAMES[state.period]}</div>
    <div class="value">${plan}</div><div class="sub">节点流量 × 倍率；含 TLS/HTTP 开销，不含代理协议开销；倍率可能与机场计费不同</div></div></div>`;
  h += `<div class="card"><h2>节点</h2>`;
  if (!d.nodes.length) {
    h += `<div class="empty">这段时间没有经过代理节点的流量</div>`;
  } else {
    h += `<table><thead><tr><th>节点</th><th class="n">流量</th><th class="n">倍率</th><th class="n">套餐消耗</th><th></th></tr></thead><tbody>` +
      d.nodes.map((n, i) => `<tr><td class="key" title="${esc(n.node)}">${esc(n.node)}</td><td class="n">${bytes(n.bytes)}</td>
        <td class="n"><input type="number" min="0" max="100" step="0.1" data-i="${i}" value="${n.multiplier}" style="width:80px;text-align:right"></td>
        <td class="n">${bytes(n.plan)}</td><td class="note">${n.configured ? "已设置" : "取自节点名或默认 1"}</td></tr>`).join("") + "</tbody></table>";
    h += `<div class="row" style="margin-top:12px"><button class="btn primary" id="save-mult">保存倍率</button><span class="note">保存在 config.json，按节点名匹配</span></div>`;
  }
  h += "</div>";
  page.innerHTML = h;
  const btn = $("#save-mult");
  if (btn) btn.addEventListener("click", async () => {
    const m = new Map(s.multipliers);
    for (const inp of page.querySelectorAll("input[data-i]")) {
      const n = d.nodes[Number(inp.dataset.i)];
      const v = Number(inp.value);
      if (!(v >= 0 && v <= 100)) { toast("倍率应为 0 到 100 之间的数", true); return; }
      if (n.configured || v !== n.multiplier) m.set(n.node, v);
    }
    try {
      await call("settings_save", { multipliers: Array.from(m.entries()) });
      toast("倍率已保存");
      render();
    } catch (e) { fail(e); }
  });
}

// ---------- unknown ----------

async function renderUnknown(current) {
  const d = await call("unknown", { period: state.period });
  if (!current()) return;
  let h = `<div class="card"><h2>没有归到任何应用的流量</h2>
    <div class="note" style="margin-bottom:10px">归类后新增一条规则，之后记录的流量按规则归类；已记录的不变。</div>`;
  if (!d.rows.length) {
    h += `<div class="empty">这段时间没有待归类的流量</div>`;
  } else {
    h += `<table class="fixed"><colgroup><col style="width:24%"><col style="width:32%"><col style="width:11%"><col style="width:33%"></colgroup>
      <thead><tr><th>进程</th><th>域名</th><th class="n">流量</th><th>归类为</th></tr></thead><tbody>` +
      d.rows.map((r, i) => `<tr><td class="key">${esc(r.process)}</td><td class="key">${r.domain ? esc(r.domain) : `<span class="zero">（无域名）</span>`}</td>
        <td class="n">${bytes(r.bytes)}</td>
        <td><form class="inline-form" data-i="${i}">
          <select name="target">${r.domain ? `<option value="${esc(r.domain)}">按域名</option>` : ""}<option value="${esc(r.process)}">按进程</option></select>
          <input type="text" name="app" placeholder="应用名" required><button class="btn">归类</button></form></td></tr>`).join("") + "</tbody></table>";
  }
  h += "</div>";
  page.innerHTML = h;
  page.querySelectorAll("form[data-i]").forEach((f) => f.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      const r = await call("classify", { target: f.target.value, app: f.app.value });
      toast("已添加规则：" + r.text);
      f.closest("tr").remove();
    } catch (err) { fail(err); }
  }));
}

// ---------- rules ----------

function ruleText(r) {
  const parts = [];
  if (r.process) parts.push("进程 " + r.process);
  if (r.domain) parts.push("域名 " + r.domain);
  return parts.join(" + ");
}

async function renderRules(current, given) {
  const d = given || await call("rules");
  if (!current()) return;
  let h = `<div class="card"><h2>我的规则</h2>`;
  if (!d.rules.length) {
    h += `<div class="empty">还没有规则；在“待归类”里归类会自动添加</div>`;
  } else {
    h += `<table><thead><tr><th>#</th><th>匹配</th><th>应用</th><th></th></tr></thead><tbody>` +
      d.rules.map((r) => `<tr><td>${r.index + 1}</td><td class="key">${esc(ruleText(r))}</td><td>${esc(r.app)}</td>
        <td class="n"><button class="btn danger" data-i="${r.index}">删除</button></td></tr>`).join("") + "</tbody></table>";
  }
  h += `<div class="note" style="margin-top:10px">用户规则优先于内置规则。同一个匹配对象再次归类会替换旧规则。只影响之后记录的流量。</div></div>`;
  h += `<div class="card"><h2>添加规则</h2><form class="form" id="add-rule">
      <label for="r-app">应用名</label><input type="text" id="r-app" name="app" required>
      <label for="r-proc">进程</label><input type="text" id="r-proc" name="process" placeholder="如 code.exe（可留空）">
      <label for="r-dom">域名</label><input type="text" id="r-dom" name="domain" placeholder="如 github.com、full:api.x.com、keyword:steam（可留空）">
      <div class="full"><button class="btn primary">添加</button></div></form></div>`;
  h += `<div class="card"><h2>内置规则</h2><div class="note">${d.builtin ? `${d.builtin} 条域名规则，来自 v2fly/domain-list-community` : "没有安装内置规则"}</div></div>`;
  page.innerHTML = h;
  page.querySelectorAll("button[data-i]").forEach((b) => b.addEventListener("click", async () => {
    try {
      const nd = await call("rule_remove", { index: Number(b.dataset.i) });
      toast("规则已删除");
      renderRules(current, nd);
    } catch (e) { fail(e); }
  }));
  $("#add-rule").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    try {
      const nd = await call("rule_add", { app: f.app.value, process: f.process.value, domain: f.domain.value });
      toast("规则已添加");
      renderRules(current, nd);
    } catch (err) { fail(err); }
  });
}

// ---------- settings ----------

async function renderSettings(current) {
  await refreshStatus();
  const [s, st] = [await call("settings"), state.status || {}];
  if (!current()) return;
  const running = st.phase === "running" || st.phase === "paused";
  let h = `<div class="card"><h2>采集进程</h2><dl class="kv">
    <dt>状态</dt><dd>${PHASE_TEXT[st.phase] || "-"}${st.detail && !running && st.phase !== "not-installed" ? `（${esc(st.detail)}）` : ""}</dd>`;
  if (running) {
    h += `<dt>模式</dt><dd>${st.degraded ? "降级：未提权，直连流量不完整" : "完整（Kernel-Network、DNS-Client、Kernel-Process）"}</dd>
      <dt>代理内核</dt><dd>${esc(st.core_link || "-")}</dd>
      <dt>启动于</dt><dd>${esc(st.since || "-")}（pid ${st.pid}）</dd>
      <dt>事件</dt><dd>${st.events}，丢失 ${st.events_lost}，队列丢弃 ${st.dropped}</dd>
      <dt>资源</dt><dd>内存 ${bytes(st.private_bytes)}，CPU ${(st.cpu_permille / 10).toFixed(1)}% 单核</dd>`;
  }
  if (st.last_error) h += `<dt>最近错误</dt><dd>${esc(st.last_error)}</dd>`;
  h += `<dt>数据目录</dt><dd>${esc(st.data_dir || "")}</dd></dl>
    <div class="row" style="margin-top:14px">
      ${st.phase === "running" ? `<button class="btn" data-act="pause">暂停采集</button>` : ""}
      ${st.phase === "paused" ? `<button class="btn" data-act="resume">恢复采集</button>` : ""}
      ${running ? `<button class="btn" data-act="stop">停止采集</button>` : ""}
      ${st.phase === "stopped" ? `<button class="btn primary" data-act="start">启动采集</button>` : ""}
    </div>
    <div class="note" style="margin-top:8px">暂停时采集进程仍在运行但不记账；停止后不再记录，直到下次启动。</div></div>`;
  h += `<div class="card"><h2>启动</h2><label class="switch"><input type="checkbox" id="autostart" ${st.autostart ? "checked" : ""}> 登录时启动（托盘图标，并开始采集）</label>
    <div class="note" style="margin-top:8px">关闭后登录时什么都不运行；只有打开 netwhere 时才采集。从托盘退出会停止采集。</div></div>`;
  h += `<div class="card"><h2>代理内核与保留</h2><form class="form" id="cfg">
      <label for="c-ctl">Clash API 地址</label><input type="text" id="c-ctl" name="controller" value="${esc(s.controller)}" placeholder="127.0.0.1:9090">
      <label for="c-sec">密钥</label><input type="password" id="c-sec" name="secret" placeholder="${s.has_secret ? "已设置；留空保持不变" : "没有设置"}" autocomplete="off">
      <label for="c-ret">保留天数</label><input type="number" id="c-ret" name="retention" min="1" max="3650" value="${s.retention_days}">
      <div class="full row"><button class="btn primary">保存</button><span class="note">保存到 config.json，采集进程 5 秒内重新读取</span></div></form></div>`;
  h += `<div class="card"><h2>导出</h2><div class="row"><select id="ex-period">${Object.keys(PERIOD_NAMES).map((p) => `<option value="${p}" ${p === "7d" ? "selected" : ""}>${PERIOD_NAMES[p]}</option>`).join("")}</select>
    <button class="btn" id="export">导出 CSV</button><span class="note">每分钟一行，与 netwhere export --csv 相同</span></div></div>`;
  page.innerHTML = h;
  page.querySelectorAll("button[data-act]").forEach((b) => b.addEventListener("click", async () => {
    b.disabled = true;
    try {
      await call("control", { action: b.dataset.act });
      toast({ pause: "已请求暂停", resume: "已请求恢复", start: "正在启动采集", stop: "采集已停止" }[b.dataset.act]);
      setTimeout(render, b.dataset.act === "stop" ? 0 : 5500);
    } catch (e) { fail(e); b.disabled = false; }
  }));
  $("#autostart").addEventListener("change", async (e) => {
    try {
      await call("autostart", { on: e.target.checked });
      toast(e.target.checked ? "登录时启动：开" : "登录时启动：关");
    } catch (err) { fail(err); e.target.checked = !e.target.checked; }
  });
  $("#cfg").addEventListener("submit", async (e) => {
    e.preventDefault();
    const f = e.target;
    const arg = { controller: f.controller.value, retention_days: Number(f.retention.value) };
    if (f.secret.value !== "") arg.secret = f.secret.value;
    try {
      await call("settings_save", arg);
      toast("设置已保存");
      render();
    } catch (err) { fail(err); }
  });
  $("#export").addEventListener("click", async () => {
    try {
      const r = await call("export", { period: $("#ex-period").value });
      if (!r.cancelled) toast(`已导出 ${r.rows} 行到 ${r.path}`);
    } catch (e) { fail(e); }
  });
}

// ---------- start ----------

go(location.hash.slice(1) || "overview");
refreshStatus();
setInterval(refreshStatus, 5000);
// Live pages follow new traffic.
setInterval(() => {
  if (document.hidden) return;
  if (state.page === "overview" && (state.period === "today" || state.period === "24h")) render();
}, 30000);
