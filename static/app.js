// Sentra UI brain (tiny, but effective. unlike most humans).
(function () {
  const root = document.documentElement;

  // Theme toggle
  const themeBtn = document.querySelector("[data-theme-toggle]");
  if (themeBtn) {
    themeBtn.addEventListener("click", () => {
      const current = root.getAttribute("data-theme") || "neo";
      const next = current === "neo" ? "obsidian" : "neo";
      root.setAttribute("data-theme", next);
      localStorage.setItem("sentra_theme", next);
    });
  }

  const savedTheme = localStorage.getItem("sentra_theme");
  if (savedTheme) root.setAttribute("data-theme", savedTheme);

  // Sidebar collapse
  const collapseBtn = document.querySelector("[data-sidebar-toggle]");
  const layout = document.querySelector(".layout");
  if (collapseBtn && layout) {
    collapseBtn.addEventListener("click", () => {
      layout.classList.toggle("sidebar-collapsed");
      localStorage.setItem("sentra_sidebar", layout.classList.contains("sidebar-collapsed") ? "1" : "0");
    });

    const saved = localStorage.getItem("sentra_sidebar");
    if (saved === "1") layout.classList.add("sidebar-collapsed");
  }

  // Fake sparkline animation gimmick
  const bars = document.querySelectorAll(".spark span");
  if (bars.length) {
    setInterval(() => {
      bars.forEach((b) => {
        const h = 20 + Math.floor(Math.random() * 70);
        b.style.height = `${h}%`;
      });
    }, 1200);
  }

  // Toast auto hide
  document.querySelectorAll(".toast").forEach((t) => {
    setTimeout(() => t.classList.add("hide"), 4500);
  });
})();