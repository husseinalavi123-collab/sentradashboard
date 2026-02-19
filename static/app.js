// Sentra UI gimmicks: particles, toasts, modal dialogs, command palette, counters, chart
(function () {
  // ---------- helpers ----------
  const $ = (q, el=document) => el.querySelector(q);
  const $$ = (q, el=document) => Array.from(el.querySelectorAll(q));

  // ---------- toasts ----------
  const toastWrap = $("#toasts");
  function toast(title, msg, ms=2600) {
    if (!toastWrap) return;
    const node = document.createElement("div");
    node.className = "toast";
    node.innerHTML = `<div class="t">${title}</div><div class="m">${msg}</div>`;
    toastWrap.appendChild(node);
    setTimeout(() => {
      node.style.opacity = "0";
      node.style.transform = "translateX(10px)";
      setTimeout(() => node.remove(), 220);
    }, ms);
  }

  // demo toast on home
  const demoToast = $("#demoToast");
  if (demoToast) demoToast.addEventListener("click", () => toast("Sentra", "Toast system online. Humans love popups."));

  // ---------- modal ----------
  const modal = $("#modal");
  const modalTitle = $("#modalTitle");
  const modalBody = $("#modalBody");
  const modalConfirm = $("#modalConfirm");

  function openModal(title, bodyHtml, onConfirm) {
    if (!modal) return;
    modalTitle.textContent = title;
    modalBody.innerHTML = bodyHtml;
    modal.classList.remove("hidden");

    modalConfirm.onclick = () => {
      closeModal();
      if (typeof onConfirm === "function") onConfirm();
    };
  }
  function closeModal() {
    if (!modal) return;
    modal.classList.add("hidden");
  }

  $$("[data-close-modal]").forEach(btn => btn.addEventListener("click", closeModal));

  const openModalBtn = $("#openModalBtn");
  if (openModalBtn) {
    openModalBtn.addEventListener("click", () => {
      openModal(
        "Discord-ish Dialog",
        `<p>This is a fake dialog, but it looks cool. Want to spawn a toast too?</p>`,
        () => toast("Confirmed", "You clicked confirm. Congratulations on your excellent clicking.")
      );
    });
  }

  // quick actions open modal
  $$("[data-action]").forEach(btn => {
    btn.addEventListener("click", () => {
      const action = btn.getAttribute("data-action");
      openModal(
        "Action",
        `<p>Run <b>${action}</b>?</p><p class="muted">This is UI-only right now. Later it can call real endpoints.</p>`,
        () => toast("Queued", `Action "${action}" queued. (In your imagination.)`)
      );
    });
  });

  // ---------- command palette ----------
  const cmdk = $("#cmdk");
  const cmdkInput = $("#cmdkInput");
  const cmdkList = $("#cmdkList");
  const openCmdkBtn = $("#openCmdk");
  const demoCmdk = $("#demoCmdk");

  const commands = [
    { title: "Overview", desc: "Go to dashboard overview", href: "/dashboard" },
    { title: "Servers", desc: "View server list", href: "/servers" },
    { title: "Reports", desc: "Open reports center", href: "/reports" },
    { title: "Settings", desc: "Open settings", href: "/settings" },
    { title: "Show Toast", desc: "A totally necessary notification", run: () => toast("Sentra", "Command Center executed: Toast.") },
    { title: "Open Dialog", desc: "Pop open a dialog", run: () => openModal("Command Dialog", "<p>Command Center opened this dialog. Very powerful.</p>", () => toast("Nice", "Confirmed from Command Center.")) },
  ];

  function renderCmdk(filter="") {
    if (!cmdkList) return;
    const f = filter.toLowerCase().trim();
    const list = commands.filter(c => (c.title + " " + c.desc).toLowerCase().includes(f));
    cmdkList.innerHTML = list.map((c, i) =>
      `<div class="cmdk-item" data-idx="${i}">
        <div class="tt">${c.title}</div>
        <div class="dd">${c.desc}</div>
      </div>`
    ).join("");
    $$(".cmdk-item", cmdkList).forEach(item => item.addEventListener("click", () => runCmdkItem(item)));
  }

  function openCmdk() {
    if (!cmdk) return;
    cmdk.classList.remove("hidden");
    renderCmdk("");
    setTimeout(() => cmdkInput && cmdkInput.focus(), 20);
  }
  function closeCmdk() {
    if (!cmdk) return;
    cmdk.classList.add("hidden");
  }

  $$("[data-close-cmdk]").forEach(btn => btn.addEventListener("click", closeCmdk));
  if (openCmdkBtn) openCmdkBtn.addEventListener("click", openCmdk);
  if (demoCmdk) demoCmdk.addEventListener("click", openCmdk);

  function runCmdkItem(el) {
    const idx = Number(el.getAttribute("data-idx"));
    const filter = (cmdkInput?.value || "").toLowerCase().trim();
    const list = commands.filter(c => (c.title + " " + c.desc).toLowerCase().includes(filter));
    const cmd = list[idx];
    if (!cmd) return;
    closeCmdk();
    if (cmd.href) window.location.href = cmd.href;
    if (cmd.run) cmd.run();
  }

  if (cmdkInput) {
    cmdkInput.addEventListener("input", () => renderCmdk(cmdkInput.value));
    cmdkInput.addEventListener("keydown", (e) => {
      if (e.key === "Escape") closeCmdk();
      if (e.key === "Enter") {
        const first = $(".cmdk-item", cmdkList);
        if (first) runCmdkItem(first);
      }
    });
  }

  document.addEventListener("keydown", (e) => {
    const k = e.key.toLowerCase();
    const meta = e.metaKey || e.ctrlKey;
    if (meta && k === "k") {
      e.preventDefault();
      openCmdk();
    }
    if (k === "escape") {
      closeCmdk();
      closeModal();
    }
  });

  // ---------- counters ----------
  function animateCount(el) {
    const target = Number(el.getAttribute("data-target") || "0");
    const duration = 900;
    const start = performance.now();
    function tick(now) {
      const p = Math.min((now - start) / duration, 1);
      const eased = 1 - Math.pow(1 - p, 3);
      const value = Math.floor(eased * target);
      el.textContent = value.toLocaleString();
      if (p < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }
  $$(".count").forEach(animateCount);

  // ---------- chart on dashboard ----------
  if (window.SENTRA_PAGE === "dashboard") {
    const weekly = window.SENTRA_WEEKLY || [12,18,9,22,31,14,27];
    const canvas = document.getElementById("joinsChart");
    if (canvas && window.Chart) {
      new Chart(canvas, {
        type: "line",
        data: {
          labels: ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"],
          datasets: [{
            data: weekly,
            tension: 0.35,
            fill: true,
            pointRadius: 3,
            pointHoverRadius: 6,
            borderWidth: 2
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: { x: { grid: { display: false } }, y: { beginAtZero: true } }
        }
      });
    }
  }

  // ---------- notifications demo ----------
  const notifyBtn = $("#notifyBtn");
  if (notifyBtn) notifyBtn.addEventListener("click", () => {
    toast("Alerts", "No incidents detected. Yet.", 2400);
  });

  // ---------- particles (lightweight) ----------
  const canvas = document.getElementById("particles");
  if (canvas) {
    const ctx = canvas.getContext("2d");
    let w = canvas.width = window.innerWidth;
    let h = canvas.height = window.innerHeight;
    const n = Math.min(90, Math.floor((w*h) / 25000));
    const pts = Array.from({length:n}, () => ({
      x: Math.random()*w,
      y: Math.random()*h,
      vx: (Math.random()-0.5)*0.5,
      vy: (Math.random()-0.5)*0.5
    }));

    function resize(){
      w = canvas.width = window.innerWidth;
      h = canvas.height = window.innerHeight;
    }
    window.addEventListener("resize", resize);

    function loop(){
      ctx.clearRect(0,0,w,h);
      ctx.globalAlpha = 0.85;

      for (const p of pts){
        p.x += p.vx; p.y += p.vy;
        if (p.x<0||p.x>w) p.vx *= -1;
        if (p.y<0||p.y>h) p.vy *= -1;
      }

      // lines
      for (let i=0;i<pts.length;i++){
        for (let j=i+1;j<pts.length;j++){
          const a=pts[i], b=pts[j];
          const dx=a.x-b.x, dy=a.y-b.y;
          const d = Math.hypot(dx,dy);
          if (d < 120){
            ctx.strokeStyle = `rgba(0,229,255,${(1 - d/120)*0.22})`;
            ctx.beginPath();
            ctx.moveTo(a.x,a.y);
            ctx.lineTo(b.x,b.y);
            ctx.stroke();
          }
        }
      }

      // points
      for (const p of pts){
        ctx.fillStyle = "rgba(0,229,255,0.35)";
        ctx.beginPath();
        ctx.arc(p.x,p.y,1.6,0,Math.PI*2);
        ctx.fill();
      }

      requestAnimationFrame(loop);
    }
    loop();
  }
})();