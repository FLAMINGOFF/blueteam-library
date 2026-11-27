// 首页“检测观测台”：规则更新流 + 3D 规则星图 + 战术频谱
// 原生 Canvas 实现，无第三方依赖。支持暂停动效、prefers-reduced-motion、离屏自动暂停。
(function () {
  const root = document.getElementById("obs");
  if (!root) return;
  const BASE = root.dataset.base || "", LANG = root.dataset.lang || "zh";
  const store = (window.BT && window.BT.store) || { get: (k, d) => d, set() {} };
  const reduce = window.matchMedia && matchMedia("(prefers-reduced-motion: reduce)").matches;
  let paused = store.get("bt-motion-paused", null);
  if (paused === null) paused = reduce;
  let visible = true;
  const pauseBtn = root.querySelector("[data-pause]");
  const LBL = LANG === "zh" ? ["暂停动效", "继续动效"] : ["Pause motion", "Resume motion"];
  function syncPause() {
    pauseBtn.setAttribute("aria-pressed", String(paused));
    pauseBtn.querySelector(".lbl").textContent = paused ? LBL[1] : LBL[0];
    root.classList.toggle("is-paused", paused);
  }
  pauseBtn.addEventListener("click", () => { paused = !paused; store.set("bt-motion-paused", paused); syncPause(); kick(); });
  syncPause();

  // ---------- 主题色 ----------
  let C = {};
  function readColors() {
    const cs = getComputedStyle(document.documentElement);
    const v = n => cs.getPropertyValue(n).trim();
    C = { text: v("--text"), muted: v("--muted"), line: v("--line"), line2: v("--line-2"), accent: v("--accent"), accent2: v("--accent-2"), panel: v("--panel") };
    C.dark = luminance(v("--bg")) < 0.4;
  }
  function luminance(hex) {
    const m = hex.replace("#", "").match(/.{2}/g); if (!m) return 1;
    const [r, g, b] = m.map(x => parseInt(x, 16) / 255); return 0.2126 * r + 0.7152 * g + 0.0722 * b;
  }
  // 战术配色：从青绿到蓝紫再到橙，15 个战术均匀取色
  const hue = i => [174, 186, 198, 210, 222, 236, 252, 268, 284, 300, 320, 340, 12, 28, 42][i % 15];
  const tcol = (i, a = 1, l) => `hsla(${hue(i)}, ${C.dark ? 80 : 70}%, ${l ?? (C.dark ? 62 : 45)}%, ${a})`;

  function fit(canvas) {
    const r = canvas.getBoundingClientRect(), dpr = Math.min(window.devicePixelRatio || 1, 2);
    const w = Math.max(1, Math.round(r.width)), h = Math.max(1, Math.round(r.height));
    if (canvas.width !== w * dpr || canvas.height !== h * dpr) { canvas.width = w * dpr; canvas.height = h * dpr; }
    const ctx = canvas.getContext("2d"); ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { ctx, w, h };
  }

  // ---------- 数据 ----------
  let D = null;
  fetch(`${BASE}/${LANG}/viz.json`).then(r => r.json()).then(d => { D = d; init(); }).catch(() => root.classList.add("obs-failed"));

  // ---------- 星图 ----------
  const star = document.getElementById("starCanvas");
  const tip = document.getElementById("starTip");
  let pts = [], hubs = [], incs = [], yaw = 0.6, pitch = (window.innerWidth < 600 ? 0.85 : 0.62), dragging = false, lastX = 0, lastY = 0, hover = -1, pulses = [], vel = 0;
  function rand(seed) { let s = seed >>> 0; return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 4294967296); }
  function buildStar() {
    const R = rand(20261123), N = D.tactics.length;
    const counts = D.tactics.map(t => t[2] || 0);
    hubs = D.tactics.map((t, i) => {
      const a = (i / N) * Math.PI * 2;
      return { i, name: t[1], id: t[0], a, x: Math.cos(a) * 250, y: 0, z: Math.sin(a) * 250, n: counts[i] };
    });
    pts = D.rules.map((r, k) => {
      const ti = r[2] < 0 ? Math.floor(R() * N) : r[2];
      // 螺旋臂：越往外越扭转，形成星系状
      const rr = 40 + Math.pow(R(), 0.7) * 230;
      const a = (ti / N) * Math.PI * 2 + rr * 0.006 + (R() - 0.5) * 0.32;
      const g = () => (R() + R() + R() - 1.5);
      return { k, ti, lv: r[3], x: Math.cos(a) * rr + g() * 10, y: g() * (28 - rr * 0.06) + Math.sin(rr * 0.05 + ti) * 10, z: Math.sin(a) * rr + g() * 10, tw: R() * 6.28 };
    });
    incs = D.incidents.map((x, j) => {
      const a = (j / D.incidents.length) * Math.PI * 2 + 0.4;
      return { j, x: Math.cos(a) * 70, y: -60 - j * 12, z: Math.sin(a) * 70, ta: x[2] };
    });
    const lg = document.getElementById("starLegend");
    lg.innerHTML = hubs.filter(h => h.n).sort((a, b) => b.n - a.n).slice(0, 8)
      .map(h => `<a href="${BASE}/${LANG}/rules/?tactic=${h.id}"><i style="background:${tcol(h.i)}"></i>${h.name}<b>${h.n}</b></a>`).join("")
      + `<span class="lg-inc"><i></i>${LANG === "zh" ? "事件复盘" : "Incident"}</span>`;
  }
  let proj = [];
  function project(p, w, h, cy, sy, cp, sp, scale) {
    const x1 = p.x * cy - p.z * sy, z1 = p.x * sy + p.z * cy;
    const y2 = p.y * cp - z1 * sp, z2 = p.y * sp + z1 * cp;
    const f = 620 / (620 + z2);
    return [w / 2 + x1 * f * scale, h * 0.5 + y2 * f * scale, f, z2];
  }
  function drawStar(t) {
    const { ctx, w, h } = fit(star);
    ctx.clearRect(0, 0, w, h);
    const scale = w < 600 ? Math.min(w / 640, h / 260) : Math.min(w / 620, h / 330);
    const cy = Math.cos(yaw), sy = Math.sin(yaw), cp = Math.cos(pitch), sp = Math.sin(pitch);
    // 轨道环
    ctx.lineWidth = 1;
    for (const r of [90, 170, 260]) {
      ctx.beginPath();
      for (let s = 0; s <= 64; s++) {
        const a = s / 64 * Math.PI * 2, q = project({ x: Math.cos(a) * r, y: 0, z: Math.sin(a) * r }, w, h, cy, sy, cp, sp, scale);
        s ? ctx.lineTo(q[0], q[1]) : ctx.moveTo(q[0], q[1]);
      }
      ctx.strokeStyle = C.line; ctx.globalAlpha = 0.9; ctx.stroke();
    }
    ctx.globalAlpha = 1;
    // 核心光晕
    const c0 = project({ x: 0, y: 0, z: 0 }, w, h, cy, sy, cp, sp, scale);
    const gr = ctx.createRadialGradient(c0[0], c0[1], 0, c0[0], c0[1], 90 * scale);
    gr.addColorStop(0, C.dark ? "rgba(45,212,191,.28)" : "rgba(14,124,134,.16)"); gr.addColorStop(1, "rgba(0,0,0,0)");
    ctx.fillStyle = gr; ctx.fillRect(c0[0] - 100 * scale, c0[1] - 100 * scale, 200 * scale, 200 * scale);

    // 事件 → 战术连线
    const hp = hubs.map(hb => project(hb, w, h, cy, sy, cp, sp, scale));
    const ip = incs.map(x => project(x, w, h, cy, sy, cp, sp, scale));
    ctx.lineWidth = 1;
    incs.forEach((x, j) => x.ta.forEach(ti => {
      ctx.beginPath(); ctx.moveTo(ip[j][0], ip[j][1]); ctx.lineTo(hp[ti][0], hp[ti][1]);
      ctx.strokeStyle = tcol(ti, C.dark ? 0.22 : 0.28); ctx.stroke();
    }));

    // 规则星点
    ctx.globalCompositeOperation = C.dark ? "lighter" : "source-over";
    proj = new Array(pts.length);
    for (let k = 0; k < pts.length; k++) {
      const p = pts[k], q = project(p, w, h, cy, sy, cp, sp, scale);
      proj[k] = q;
      const tw = paused ? 1 : 0.75 + 0.25 * Math.sin(t * 0.002 + p.tw);
      const sz = (p.lv <= 1 ? 1.9 : p.lv === 2 ? 1.4 : 1.05) * q[2] * scale * (k === hover ? 2.6 : 1);
      ctx.fillStyle = tcol(p.ti, Math.min(1, (0.35 + 0.55 * q[2] - 0.15) * tw));
      ctx.fillRect(q[0] - sz / 2, q[1] - sz / 2, sz, sz);
      // 严重/高：竖直“信号针”
      if (p.lv === 0) { ctx.fillRect(q[0] - 0.5, q[1] - 10 * q[2] * scale, 1, 10 * q[2] * scale); }
    }
    ctx.globalCompositeOperation = "source-over";

    // 汇入脉冲
    pulses = pulses.filter(pl => t - pl.t0 < 1600);
    for (const pl of pulses) {
      const q = proj[pl.k]; if (!q) continue;
      const e = (t - pl.t0) / 1600;
      ctx.beginPath(); ctx.arc(q[0], q[1], 4 + e * 22, 0, 6.283);
      ctx.strokeStyle = tcol(pts[pl.k].ti, 1 - e); ctx.lineWidth = 1.5; ctx.stroke();
    }

    // 事件节点
    ip.forEach(q => {
      const r = 4.5 * q[2] * scale;
      ctx.beginPath(); ctx.arc(q[0], q[1], r + 3, 0, 6.283); ctx.strokeStyle = C.accent; ctx.globalAlpha = 0.5; ctx.stroke();
      ctx.globalAlpha = 1; ctx.beginPath(); ctx.arc(q[0], q[1], r, 0, 6.283); ctx.fillStyle = C.accent; ctx.fill();
    });

    // 战术标签（只标前面的、规则多的）
    ctx.font = `600 ${Math.max(10, 11.5 * scale)}px ${getComputedStyle(document.body).fontFamily}`;
    ctx.textAlign = "center";
    hubs.forEach((hb, i) => {
      if (!hb.n) return;
      const q = hp[i]; if (q[3] > 120) return;
      ctx.fillStyle = tcol(i, Math.min(1, 0.5 + q[2] * 0.5), C.dark ? 70 : 38);
      ctx.fillText(hb.name, q[0], q[1] - 14 * q[2]);
    });
  }
  function nearest(mx, my) {
    let best = -1, bd = 100;
    for (let k = 0; k < proj.length; k++) {
      const q = proj[k]; if (!q) continue;
      const d = (q[0] - mx) ** 2 + (q[1] - my) ** 2;
      if (d < bd) { bd = d; best = k; }
    }
    return best;
  }
  function showTip(k, mx, my) {
    if (k < 0) { tip.hidden = true; star.style.cursor = dragging ? "grabbing" : "grab"; return; }
    const r = D.rules[pts[k].k], tn = r[2] >= 0 ? D.tactics[r[2]][1] : "";
    tip.innerHTML = `<span style="color:${tcol(pts[k].ti)}">● ${tn}</span><b>${r[1].replace(/[<>&]/g, "")}</b><small>${r[4]}</small>`;
    tip.hidden = false;
    const bw = star.clientWidth;
    tip.style.left = Math.min(mx + 14, bw - 260) + "px"; tip.style.top = (my + 14) + "px";
    star.style.cursor = "pointer";
  }
  function bindStar() {
    const pos = e => { const r = star.getBoundingClientRect(); const s = e.touches ? e.touches[0] : e; return [s.clientX - r.left, s.clientY - r.top]; };
    let moved = 0;
    const down = e => { dragging = true; moved = 0; [lastX, lastY] = pos(e); star.style.cursor = "grabbing"; };
    const move = e => {
      const [x, y] = pos(e);
      if (dragging) {
        const dx = x - lastX, dy = y - lastY; moved += Math.abs(dx) + Math.abs(dy);
        yaw += dx * 0.006; vel = dx * 0.006; pitch = Math.max(-1.2, Math.min(1.2, pitch + dy * 0.005));
        lastX = x; lastY = y; if (e.cancelable && e.touches) e.preventDefault(); kick();
      } else { hover = nearest(x, y); showTip(hover, x, y); if (paused) kick(); }
    };
    const up = e => {
      if (dragging && moved < 5) {
        const [x, y] = e.changedTouches ? [e.changedTouches[0].clientX - star.getBoundingClientRect().left, e.changedTouches[0].clientY - star.getBoundingClientRect().top] : pos(e);
        const k = nearest(x, y);
        if (k >= 0) location.href = `${BASE}/${LANG}/rules/${D.rules[pts[k].k][0]}/`;
      }
      dragging = false;
    };
    star.addEventListener("mousedown", down); window.addEventListener("mousemove", e => { if (dragging || e.target === star) move(e); });
    window.addEventListener("mouseup", up);
    star.addEventListener("mouseleave", () => { hover = -1; tip.hidden = true; if (paused) kick(); });
    star.addEventListener("touchstart", down, { passive: true }); star.addEventListener("touchmove", move, { passive: false }); star.addEventListener("touchend", up);
  }

  // ---------- 频谱 ----------
  const spec = document.getElementById("specCanvas");
  let bars = [], counts = [];
  function buildSpec() {
    counts = D.tactics.map(t => t[2] || 0);
    const mx = Math.max(...counts);
    bars = counts.map((n, i) => ({ i, n, base: n ? 0.18 + 0.82 * Math.log1p(n) / Math.log1p(mx) : 0.04, cur: 0, kick: 0, ph: i * 0.7 }));
  }
  function drawSpec(t) {
    const { ctx, w, h } = fit(spec);
    ctx.clearRect(0, 0, w, h);
    const n = bars.length, labelH = 18, gap = Math.max(3, w * 0.012), bw = (w - gap * (n - 1)) / n, seg = 4, sgap = 2;
    const H = h - labelH - 4;
    ctx.font = `10px ${getComputedStyle(document.body).fontFamily}`; ctx.textAlign = "center";
    bars.forEach((b, i) => {
      const jit = paused ? 0 : 0.05 * Math.sin(t * 0.004 + b.ph) + 0.03 * Math.sin(t * 0.011 + b.ph * 2);
      b.kick *= 0.93;
      const target = Math.max(0.03, Math.min(1, b.base + jit + b.kick));
      b.cur += (target - b.cur) * (paused ? 1 : 0.18);
      const x = i * (bw + gap), segs = Math.floor(H / (seg + sgap)), lit = Math.round(segs * b.cur);
      for (let s = 0; s < segs; s++) {
        const y = H - (s + 1) * (seg + sgap) + sgap;
        ctx.fillStyle = s < lit ? tcol(i, 0.35 + 0.65 * (s / segs) + 0.1) : (C.dark ? "rgba(255,255,255,.035)" : "rgba(15,23,38,.045)");
        ctx.fillRect(x, y, bw, seg);
      }
      // 峰值帽
      const py = H - lit * (seg + sgap) - 3;
      ctx.fillStyle = tcol(i, 1, C.dark ? 75 : 40); ctx.fillRect(x, py, bw, 2);
      ctx.fillStyle = C.muted;
      if (bw > 26) ctx.fillText(D.tactics[i][1].slice(0, LANG === "zh" ? 4 : 6), x + bw / 2, h - 4);
    });
  }
  function bindSpec() {
    spec.addEventListener("click", e => {
      const r = spec.getBoundingClientRect(), i = Math.floor((e.clientX - r.left) / (r.width / bars.length));
      if (bars[i] && bars[i].n) location.href = `${BASE}/${LANG}/rules/?tactic=${D.tactics[i][0]}`;
    });
    spec.addEventListener("mousemove", e => {
      const r = spec.getBoundingClientRect(), i = Math.floor((e.clientX - r.left) / (r.width / bars.length));
      spec.title = bars[i] ? `${D.tactics[i][1]} · ${bars[i].n}` : "";
    });
    spec.style.cursor = "pointer";
  }

  // ---------- 规则更新流 ----------
  const card = document.getElementById("streamCard"), list = document.getElementById("streamList");
  let order = [], cursor = 0, lastEmit = 0;
  const LV = LANG === "zh" ? ["严重", "高", "中", "低", "信息"] : ["Critical", "High", "Medium", "Low", "Info"];
  const LVC = ["critical", "high", "medium", "low", "informational"];
  const esc = s => String(s).replace(/[&<>"]/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));
  function buildStream() {
    order = D.rules.map((r, k) => k).sort((a, b) => D.rules[b][4].localeCompare(D.rules[a][4])).slice(0, 40);
    const initial = order.slice(1, 7).map(k => li(k)).join("");
    list.innerHTML = initial;
    setCard(order[0]); cursor = 1;
  }
  function li(k) {
    const r = D.rules[k], ti = r[2];
    return `<li><a href="${BASE}/${LANG}/rules/${r[0]}/"><i style="background:${ti >= 0 ? tcol(ti) : C.muted}"></i><time>${r[4].slice(5)}</time><span>${esc(r[1])}</span></a></li>`;
  }
  function setCard(k) {
    const r = D.rules[k], tn = r[2] >= 0 ? D.tactics[r[2]][1] : "—";
    card.innerHTML = `<a href="${BASE}/${LANG}/rules/${r[0]}/">
      <div class="sc-top"><span class="sev sev-${LVC[r[3]]}">${LV[r[3]]}</span><span class="badge">${esc(tn)}</span><time>${r[4]}</time></div>
      <div class="sc-title">${esc(r[1])}</div>
      <div class="sc-foot"><span>SigmaHQ</span><span class="mono">${LANG === "zh" ? "汇入星图" : "Into the map"} →</span></div></a>`;
    card.classList.remove("flash"); void card.offsetWidth; card.classList.add("flash");
  }
  function emit(t) {
    const k = order[cursor % order.length]; cursor++;
    const prev = card.querySelector("a");
    if (prev) { list.insertAdjacentHTML("afterbegin", li(order[(cursor - 2 + order.length) % order.length])); while (list.children.length > 6) list.lastElementChild.remove(); }
    setCard(k);
    const p = pts.findIndex(x => x.k === k); if (p >= 0) pulses.push({ k: p, t0: t });
    const ti = D.rules[k][2]; if (bars[ti]) bars[ti].kick = 0.35;
  }

  // ---------- 主循环 ----------
  let raf = 0, fc = 0;
  function frame(t) {
    raf = 0;
    if (!D) return;
    if (!paused && !dragging) { vel *= 0.95; yaw += 0.0016 + vel * 0.1; }
    if (!paused && t - lastEmit > 2600) { lastEmit = t; emit(t); }
    if (++fc % 60 === 0) readColors();
    drawStar(t); drawSpec(t);
    if (!paused && visible && !document.hidden) raf = requestAnimationFrame(frame);
  }
  function kick() { if (!raf) raf = requestAnimationFrame(frame); }
  function init() {
    readColors(); buildStar(); buildSpec(); buildStream(); bindStar(); bindSpec();
    root.classList.add("obs-ready");
    kick();
  }
  if ("IntersectionObserver" in window) new IntersectionObserver(es => { visible = es[0].isIntersecting; if (visible) kick(); }).observe(root);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) kick(); });
  window.addEventListener("resize", () => kick());
  new MutationObserver(() => { readColors(); kick(); }).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
  if (window.matchMedia) matchMedia("(prefers-color-scheme: dark)").addEventListener?.("change", () => { readColors(); kick(); });
})();
