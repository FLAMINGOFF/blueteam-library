// 列表页 / 搜索页 / 收藏页的客户端筛选与渲染
(function () {
  const root = document.getElementById("list-app");
  if (!root) return;
  const cfg = JSON.parse(document.getElementById("list-cfg").textContent);
  const { base: BASE, lang, mode, L, tactics, levels, statuses } = cfg; // mode: rules | incidents | search | starred
  const PAGE = 30;
  const esc = s => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const tn = id => (tactics[id] || {})[lang] || id;
  const ln = l => (levels[l] || {})[lang] || l;
  const sn = s => (statuses[s] || {})[lang] || s;
  const FACETS = {
    rules: [["source", "src", L.sourceFacet], ["tactic", "ta", L.tactic, tn], ["platform", "pf", L.platform], ["level", "lv", L.level, ln], ["status", "st", L.status, sn]],
    incidents: [["tactic", "ta", L.tactic, tn], ["sector", "sec", L.sector], ["level", "lv", L.level, ln], ["tag", "tg", L.tags]]
  };
  let data = [], shown = PAGE;
  // 结果数用一个常驻的 live region 播报（root 每次整体重绘，放在里面读屏软件读不到变化）
  const live = document.createElement("p");
  live.className = "sr-only"; live.setAttribute("role", "status");
  root.after(live);

  function hl(text, q) {
    const safe = esc(text);
    if (!q) return safe;
    const words = q.trim().split(/\s+/).filter(Boolean).map(w => esc(w).replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
    return words.length ? safe.replace(new RegExp(words.join("|"), "gi"), m => `<mark>${m}</mark>`) : safe;
  }
  const hay = o => (o._h ??= [o.id, o.t, o.te, o.s, o.au, o.ac, o.sec, o.src, (o.te2 || []).join(" "), (o.ta || []).map(x => tn(x) + " " + x).join(" "), (o.tg || []).join(" ")].join(" ").toLowerCase());
  const match = (o, q) => !q || q.toLowerCase().split(/\s+/).filter(Boolean).every(w => hay(o).includes(w));
  const vals = (o, f) => [].concat(o[f] ?? []);

  function card(o, q) {
    const isR = o.k === "r";
    const href = `${BASE}/${lang}/${isR ? "rules" : "incidents"}/${o.id}/`;
    const key = (isR ? "r:" : "i:") + o.id;
    const meta = isR
      ? [(o.ta || []).map(tn).join(" / "), (o.te2 || []).slice(0, 4).join(", "), o.pf, o.au && (L.author + ": " + o.au), o.d]
      : [o.d, o.src, o.ac, o.sec];
    // 标题是链接（::after 盖满整张卡片），收藏按钮是它的兄弟元素，避免把按钮嵌在链接里
    return `<article class="card"><button class="star" type="button" data-star="${esc(key)}" aria-pressed="false" aria-label="${esc(L.save + ": " + o.t)}">☆</button>
      <div class="row1">${o.og ? `<span class="badge og">${esc(L.original)}</span>` : ""}<span class="badge">${isR ? L.rules : L.incidents}</span><span class="sev sev-${esc(o.lv)}">${esc(ln(o.lv))}</span>${isR ? `<span class="badge fmt">Sigma</span><span class="badge">${esc(sn(o.st))}</span>` : ""}</div>
      <a class="title" style="margin-top:6px" href="${href}">${hl(o.t, q)}</a>
      <div class="sum">${hl(o.s, q)}</div>
      <div class="meta">${meta.filter(Boolean).map(m => `<span>${esc(m)}</span>`).join("")}</div></article>`;
  }

  function state() { return new URLSearchParams(location.search); }
  function push(p) { history.replaceState(null, "", location.pathname + (p.toString() ? "?" + p : "")); shown = PAGE; render(); }

  // 重绘前记住焦点在哪个控件上，重绘后放回去，键盘用户点筛选不会丢焦点
  function focusKey() {
    const a = document.activeElement;
    if (!a || !root.contains(a)) return null;
    if (a.dataset.f) return `[data-f="${a.dataset.f}"][data-v="${CSS.escape(a.dataset.v)}"]`;
    if (a.dataset.star) return `[data-star="${CSS.escape(a.dataset.star)}"]`;
    if (a.id) return "#" + a.id;
    if (a.name === "q") return "input[name=q]";
    return null;
  }

  function render() {
    const fk = focusKey();
    draw();
    const el = fk && root.querySelector(fk);
    if (el) el.focus();
  }

  function draw() {
    const p = state(), q = p.get("q") || "", sort = p.get("sort") || "new";
    let pool = data;
    if (mode === "rules") pool = data.filter(o => o.k === "r");
    if (mode === "incidents") pool = data.filter(o => o.k === "i");
    if (mode === "starred") { const s = window.BT.stars(); pool = data.filter(o => s.has((o.k === "r" ? "r:" : "i:") + o.id)); }
    const base = pool.filter(o => match(o, q));
    const facets = FACETS[mode] || [];
    const items = base.filter(o => facets.every(([key, f]) => { const sel = p.getAll(key); return !sel.length || sel.some(v => vals(o, f).includes(v)); }));
    items.sort(sort === "sev" ? (a, b) => a.lr - b.lr || b.d.localeCompare(a.d) : (a, b) => b.d.localeCompare(a.d));

    const fHtml = facets.map(([key, f, label, nm]) => {
      const counts = {};
      base.forEach(o => vals(o, f).forEach(v => counts[v] = (counts[v] || 0) + 1));
      let keys = Object.keys(counts);
      if (key === "tactic") keys = Object.keys(tactics).filter(k => counts[k]);
      else if (key === "level") keys = Object.keys(levels).filter(k => counts[k]);
      else keys.sort((a, b) => counts[b] - counts[a]);
      const sel = p.getAll(key);
      return `<h2 class="facet">${esc(label)}</h2><div class="chips" role="group" aria-label="${esc(label)}">${keys.slice(0, 24).map(v =>
        `<button type="button" class="chip ${sel.includes(v) ? "on" : ""}" aria-pressed="${sel.includes(v)}" data-f="${key}" data-v="${esc(v)}">${esc(nm ? nm(v) : v)}<span class="c">${counts[v]}</span></button>`).join("")}</div>`;
    }).join("");
    const anyF = q || facets.some(([k]) => p.getAll(k).length);

    root.innerHTML = `
      <form class="search" id="lq" role="search"><input name="q" type="search" aria-label="${esc(L.search)}" value="${esc(q)}" placeholder="${esc(L.searchPh)}" autocomplete="off"><button class="btn">${esc(L.search)}</button></form>
      <div class="${facets.length ? "layout" : ""}">
        ${facets.length ? `<aside class="panel filters">${fHtml}${anyF ? `<p><a href="${location.pathname}">${esc(L.clear)}</a></p>` : ""}</aside>` : ""}
        <section>
          <div class="toolbar"><span class="muted small">${items.length} ${esc(L.results)}</span>
            <select id="sort" aria-label="${esc(L.sort)}"><option value="new" ${sort === "new" ? "selected" : ""}>${esc(L.sortNew)}</option><option value="sev" ${sort === "sev" ? "selected" : ""}>${esc(L.sortSev)}</option></select></div>
          ${items.length ? items.slice(0, shown).map(o => card(o, q)).join("") : `<div class="empty">${esc(mode === "starred" && !q ? L.starredEmpty : L.noResults)}</div>`}
          ${items.length > shown ? `<button class="btn ghost more-btn" id="more">${esc(L.more)} (${items.length - shown})</button>` : ""}
        </section>
      </div>`;
    window.BT.paintStars(root);
    live.textContent = `${items.length} ${L.results}`;
  }

  root.addEventListener("click", e => {
    const c = e.target.closest("[data-f]");
    if (c) {
      const p = state(), k = c.dataset.f, v = c.dataset.v, cur = p.getAll(k);
      p.delete(k); (cur.includes(v) ? cur.filter(x => x !== v) : [...cur, v]).forEach(x => p.append(k, x)); push(p); return;
    }
    if (e.target.id === "more") {
      const before = root.querySelectorAll(".card").length;
      shown += PAGE * 2; render();
      // 加载更多后把焦点移到第一张新卡片
      root.querySelectorAll(".card a.title")[before]?.focus();
    }
    if (mode === "starred" && e.target.closest("[data-star]")) setTimeout(render, 0);
  });
  root.addEventListener("submit", e => {
    e.preventDefault(); const p = state(); const q = new FormData(e.target).get("q").trim();
    q ? p.set("q", q) : p.delete("q"); push(p);
  });
  root.addEventListener("change", e => { if (e.target.id === "sort") { const p = state(); p.set("sort", e.target.value); push(p); } });

  fetch(`${BASE}/${lang}/index.json`).then(r => r.json()).then(j => { data = [...j.rules, ...j.incidents]; render(); });
})();
