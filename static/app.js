(() => {
  // Theme toggle
  const root = document.documentElement;
  const saved = localStorage.getItem("sentra_theme");
  if (saved) root.dataset.theme = saved;

  document.querySelectorAll("[data-theme-toggle]").forEach(btn => {
    btn.addEventListener("click", () => {
      const next = (root.dataset.theme === "neo") ? "obsidian" : "neo";
      root.dataset.theme = next;
      localStorage.setItem("sentra_theme", next);
    });
  });

  // Sidebar collapse
  const layout = document.querySelector(".layout");
  const savedSide = localStorage.getItem("sentra_sidebar");
  if (layout && savedSide === "1") layout.classList.add("sidebar-collapsed");

  const sideBtn = document.querySelector("[data-sidebar-toggle]");
  if (layout && sideBtn) {
    sideBtn.addEventListener("click", () => {
      layout.classList.toggle("sidebar-collapsed");
      localStorage.setItem("sentra_sidebar", layout.classList.contains("sidebar-collapsed") ? "1" : "0");
    });
  }

  // Toast auto hide
  document.querySelectorAll(".toast").forEach(t => {
    setTimeout(() => t.classList.add("hide"), 4500);
  });

  // Fake sparkline gimmick (pure dopamine)
  const bars = document.querySelectorAll(".spark span");
  if (bars.length) {
    setInterval(() => {
      bars.forEach(b => {
        const h = 18 + Math.floor(Math.random() * 75);
        b.style.height = h + "%";
      });
    }, 1200);
  }
})();