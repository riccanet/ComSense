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

  // Repeated-row editors (Configurations): add a row from the table's <template>, remove a row.
  var rowSeq = 0;
  document.addEventListener("click", function (ev) {
    var add = ev.target.closest ? ev.target.closest("[data-add-row]") : null;
    if (add) {
      var id = add.getAttribute("data-add-row");
      var tpl = document.getElementById(id + "-template");
      var body = document.getElementById(id);
      if (tpl && body) {
        rowSeq += 1;
        body.insertAdjacentHTML("beforeend", tpl.innerHTML.replace(/__KEY__/g, "n" + Date.now() + rowSeq));
        var first = body.lastElementChild && body.lastElementChild.querySelector("input:not([type=hidden]), select, textarea");
        if (first) first.focus();
      }
      return;
    }
    var remove = ev.target.closest ? ev.target.closest("[data-remove-row]") : null;
    if (remove) {
      var row = remove.closest("tr");
      if (row) row.remove();
    }
  });

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
    if (el.hasAttribute("data-autosubmit-select") && el.form) {
      el.form.submit();
      return;
    }
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
  // Pages that follow the firewall (the device page) reload when the server says something changed,
  // e.g. a task finished after "Check now". Not while the user is in the middle of a form.
  var poller = document.querySelector("[data-poll]");
  if (poller && window.fetch) {
    var token = poller.getAttribute("data-poll-token");
    var dirty = false;
    document.addEventListener("input", function () { dirty = true; });
    window.setInterval(function () {
      if (document.hidden || dirty) return;
      var active = document.activeElement;
      if (active && /^(INPUT|SELECT|TEXTAREA)$/.test(active.tagName)) return;
      fetch(poller.getAttribute("data-poll"), { credentials: "same-origin", headers: { Accept: "application/json" } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (data) {
          if (data && data.token && data.token !== token) window.location.reload();
        })
        .catch(function () {});
    }, 4000);
  }
  // Firewalls waiting for approval: the banner under the navigation bar refreshes itself, so a new
  // firewall shows up on whatever page is open.
  var banner = document.querySelector("[data-pending-banner]");
  if (banner && window.fetch) {
    window.setInterval(function () {
      if (document.hidden) return;
      if (banner.contains(document.activeElement)) return;
      var url = banner.getAttribute("data-pending-banner") + "?page=" + encodeURIComponent(location.pathname + location.search);
      fetch(url, { credentials: "same-origin", headers: { Accept: "text/html" } })
        .then(function (r) { return r.ok ? r.text() : null; })
        .then(function (html) { if (html !== null && html.trim() !== banner.innerHTML.trim()) banner.innerHTML = html; })
        .catch(function () {});
    }, 15000);
  }
})();
