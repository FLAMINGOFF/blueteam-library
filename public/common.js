// 主题切换、收藏、复制：所有页面共用
(function () {
  const store = {
    get(k, d) { try { const v = localStorage.getItem(k); return v == null ? d : JSON.parse(v); } catch { return d; } },
    set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* 隐私模式等情况下存储不可用，忽略 */ } }
  };
  window.BT = { store };
  const stars = () => new Set(store.get("bt-stars", []));
  window.BT.stars = stars;
  function paintStars(root) {
    const s = stars();
    (root || document).querySelectorAll("[data-star]").forEach(b => {
      const on = s.has(b.dataset.star); b.classList.toggle("on", on); b.textContent = on ? "★" : "☆"; b.setAttribute("aria-pressed", String(on));
    });
  }
  window.BT.paintStars = paintStars;
  function setTheme(t) {
    document.documentElement.dataset.theme = t; store.set("bt-theme", t);
    document.querySelectorAll("[data-theme-set]").forEach(b => { const on = b.dataset.themeSet === t; b.classList.toggle("on", on); b.setAttribute("aria-pressed", String(on)); });
  }
  setTheme(store.get("bt-theme", "system"));
  paintStars();
  document.addEventListener("click", e => {
    const th = e.target.closest("[data-theme-set]");
    if (th) { setTheme(th.dataset.themeSet); return; }
    const st = e.target.closest("[data-star]");
    if (st) {
      e.preventDefault(); e.stopPropagation();
      const s = stars(); s.has(st.dataset.star) ? s.delete(st.dataset.star) : s.add(st.dataset.star);
      store.set("bt-stars", [...s]); paintStars(); return;
    }
    const cp = e.target.closest("[data-copy]");
    if (cp) {
      const code = cp.parentElement.querySelector("pre").innerText;
      const ok = cp.dataset.ok || "Copied", label = cp.textContent;
      (navigator.clipboard ? navigator.clipboard.writeText(code) : Promise.reject()).then(
        () => { cp.textContent = ok; setTimeout(() => cp.textContent = label, 1500); }, () => {});
    }
  });
})();
