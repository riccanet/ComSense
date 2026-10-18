// Small progressive enhancements. Kept in a static file so the CSP can forbid inline script.
(function () {
  "use strict";

  document.addEventListener("submit", function (ev) {
    var form = ev.target;
    var msg = form.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) {
      ev.preventDefault();
      return;
    }
    if (form.hasAttribute("data-confirm-select")) {
      var sel = form.querySelector("select[name=task_type]");
      var risky = { reboot: 1, upgrade_system: 1, upgrade_packages: 1 };
      if (sel && risky[sel.value] && !window.confirm("Run \"" + sel.options[sel.selectedIndex].text + "\" on this firewall?")) {
        ev.preventDefault();
      }
    }
  });

  // Theme: stored in a cookie so the server renders the right theme on the next page load.
  function setTheme(theme) {
    document.documentElement.setAttribute("data-theme", theme);
    document.cookie = "csfm_theme=" + theme + "; path=/; max-age=31536000; SameSite=Lax" +
      (location.protocol === "https:" ? "; Secure" : "");
    document.querySelectorAll("[data-theme-set]").forEach(function (b) {
      b.setAttribute("aria-pressed", b.getAttribute("data-theme-set") === theme ? "true" : "false");
    });
    drawMetrics();
  }
  if (window.matchMedia) {
    // In auto mode, redraw the chart when the operating system switches theme.
    var mq = window.matchMedia("(prefers-color-scheme: dark)");
    var onChange = function () { drawMetrics(); };
    if (mq.addEventListener) { mq.addEventListener("change", onChange); } else if (mq.addListener) { mq.addListener(onChange); }
  }

  document.addEventListener("click", function (ev) {
    var themeBtn = ev.target.closest ? ev.target.closest("[data-theme-set]") : null;
    if (themeBtn) {
      setTheme(themeBtn.getAttribute("data-theme-set"));
      return;
    }
    var el = ev.target;
    if (el.hasAttribute("data-back") && window.history.length > 1) {
      ev.preventDefault();
      window.history.back();
    }
    var copyId = el.getAttribute("data-copy");
    if (copyId) {
      var input = document.getElementById(copyId);
      input.select();
      if (navigator.clipboard) {
        navigator.clipboard.writeText(input.value).then(function () { el.textContent = "Copied"; });
      }
    }
  });

  document.addEventListener("change", function (ev) {
    var el = ev.target;
    // Lists with a checkbox per row that saves as soon as it is ticked (Settings > Users).
    if (el.form && el.form.hasAttribute("data-autosubmit")) {
      el.form.submit();
      return;
    }
    var name = el.getAttribute("data-select-all");
    if (name) {
      document.querySelectorAll("input[name=" + name + "]").forEach(function (cb) { cb.checked = el.checked; });
    }
    if (el.id === "policy-type") {
      var examples = document.getElementById("policy-examples");
      var content = document.getElementById("policy-content");
      if (examples && content) {
        var map = JSON.parse(examples.textContent);
        if (!content.value.trim() || window.confirm("Replace the content with the example for this type?")) {
          content.value = map[el.value] || "{}";
        }
      }
    }
  });

  function drawMetrics() {
    var canvas = document.getElementById("metrics-chart");
    var dataEl = document.getElementById("metrics-data");
    if (!canvas || !dataEl) return;
    var points = JSON.parse(dataEl.textContent);
    var ctx = canvas.getContext("2d");
    var w = canvas.width, h = canvas.height, pad = 4;
    var style = getComputedStyle(document.documentElement);
    ctx.clearRect(0, 0, w, h);
    ctx.strokeStyle = style.getPropertyValue("--line");
    ctx.strokeRect(0.5, 0.5, w - 1, h - 1);
    if (points.length < 2) {
      ctx.fillStyle = style.getPropertyValue("--muted");
      ctx.fillText("Not enough data yet", 10, h / 2);
      return;
    }
    function line(key, color) {
      ctx.beginPath();
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.5;
      var started = false;
      points.forEach(function (p, i) {
        if (p[key] === null || p[key] === undefined) return;
        var x = pad + (i / (points.length - 1)) * (w - 2 * pad);
        var y = h - pad - (Math.min(100, p[key]) / 100) * (h - 2 * pad);
        if (!started) { ctx.moveTo(x, y); started = true; } else { ctx.lineTo(x, y); }
      });
      ctx.stroke();
    }
    line("cpu", style.getPropertyValue("--chart-cpu"));
    line("mem", style.getPropertyValue("--chart-mem"));
  }
  document.addEventListener("DOMContentLoaded", drawMetrics);
})();
