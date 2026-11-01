// Small progressive enhancements. Kept in a static file so the CSP can forbid inline script.
(function () {
  "use strict";
  document.documentElement.classList.add("js");

  // Phones: the Menu button opens and closes the navigation (style.css folds it).
  document.addEventListener("click", function (ev) {
    var btn = ev.target.closest && ev.target.closest("[data-menu-toggle]");
    if (!btn) return;
    var bar = btn.closest(".topbar");
    var open = bar.classList.toggle("menu-open");
    btn.setAttribute("aria-expanded", open ? "true" : "false");
  });

  // Wide tables scroll sideways inside their own box rather than widening the page (small screens).
  document.addEventListener("DOMContentLoaded", function () {
    document.querySelectorAll("main table").forEach(function (table) {
      if (table.closest(".table-scroll")) return;
      var box = document.createElement("div");
      box.className = "table-scroll";
      table.parentNode.insertBefore(box, table);
      box.appendChild(table);
    });
  });

  document.addEventListener("submit", function (ev) {
    var form = ev.target;
    var msg = form.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) {
      ev.preventDefault();
      return;
    }
    var submitter = ev.submitter;
    if (form.hasAttribute("data-confirm-select") && !(submitter && submitter.hasAttribute("data-no-confirm"))) {
      // The select may sit outside the form (form="..."): form.elements finds it either way.
      var sel = form.elements.namedItem("task_type") || form.querySelector("select[name=task_type]");
      var risky = { reboot: 1, upgrade_system: 1, upgrade_packages: 1, latest_branch: 1 };
      var where = form.id === "bulk" ? "the selected firewalls" : "this firewall";
      if (sel && risky[sel.value] && !window.confirm("Run \"" + sel.options[sel.selectedIndex].text + "\" on " + where + "?")) {
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

  // Firewall page: CPU and memory over 24 hours, one small chart each (5-minute averages from the server),
  // with a faint grid, time labels, a gap where the firewall did not report, and a crosshair readout.
  var chartHover = {};
  function drawMetrics() {
    var dataEl = document.getElementById("metrics-data");
    if (!dataEl) return;
    var points = JSON.parse(dataEl.textContent);
    var style = getComputedStyle(document.documentElement);
    document.querySelectorAll("[data-chart]").forEach(function (fig) {
      drawChart(fig, points, fig.getAttribute("data-chart"), style);
    });
  }
  function timeLabel(t, withMinutes) {
    var d = new Date(t);
    return d.toLocaleTimeString([], withMinutes ? { hour: "numeric", minute: "2-digit" } : { hour: "numeric" });
  }
  function drawChart(fig, points, key, style) {
    var canvas = fig.querySelector("canvas");
    var readout = fig.querySelector(".spark-readout");
    var dpr = window.devicePixelRatio || 1;
    var cssW = canvas.clientWidth || 420, cssH = canvas.clientHeight || 96;
    canvas.width = Math.round(cssW * dpr);
    canvas.height = Math.round(cssH * dpr);
    var ctx = canvas.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssW, cssH);
    var color = style.getPropertyValue("--chart-" + key).trim();
    var grid = style.getPropertyValue("--line").trim();
    var muted = style.getPropertyValue("--muted").trim();
    var left = 30, right = 4, top = 6, bottom = 16;
    var w = cssW - left - right, h = cssH - top - bottom;
    ctx.font = "10px system-ui, sans-serif";
    // Grid: 0, 50 and 100%, labelled; recessive.
    ctx.lineWidth = 1;
    [0, 50, 100].forEach(function (v) {
      var y = Math.round(top + h - (v / 100) * h) + 0.5;
      ctx.strokeStyle = grid;
      ctx.globalAlpha = v === 0 ? 1 : 0.6;
      ctx.beginPath(); ctx.moveTo(left, y); ctx.lineTo(left + w, y); ctx.stroke();
      ctx.globalAlpha = 1;
      ctx.fillStyle = muted;
      ctx.textAlign = "right"; ctx.textBaseline = "middle";
      ctx.fillText(v + "%", left - 5, y);
    });
    var data = points.filter(function (p) { return p[key] !== null && p[key] !== undefined; });
    if (data.length < 2) {
      ctx.fillStyle = muted; ctx.textAlign = "left";
      ctx.fillText("Not enough data yet", left + 8, top + h / 2);
      if (readout) readout.textContent = "";
      return;
    }
    var t0 = data[0].t, t1 = data[data.length - 1].t, span = Math.max(1, t1 - t0);
    var xOf = function (t) { return left + ((t - t0) / span) * w; };
    var yOf = function (v) { return top + h - (Math.min(100, Math.max(0, v)) / 100) * h; };
    // Time labels every 6 hours, on the hour.
    ctx.textAlign = "center"; ctx.textBaseline = "top"; ctx.fillStyle = muted;
    var tick = new Date(t0); tick.setMinutes(0, 0, 0);
    while (tick.getHours() % 6 !== 0 || tick.getTime() < t0) { tick = new Date(tick.getTime() + 3600000); }
    for (; tick.getTime() <= t1; tick = new Date(tick.getTime() + 6 * 3600000)) {
      var tx = xOf(tick.getTime());
      if (tx > left + 12 && tx < left + w - 12) ctx.fillText(timeLabel(tick.getTime(), false), tx, top + h + 4);
    }
    // Runs of readings, split where the firewall was silent for more than 15 minutes.
    var runs = [], run = [];
    data.forEach(function (p, i) {
      if (i && p.t - data[i - 1].t > 15 * 60000) { runs.push(run); run = []; }
      run.push(p);
    });
    runs.push(run);
    runs.forEach(function (r) {
      if (r.length < 2) return;
      ctx.beginPath();
      ctx.moveTo(xOf(r[0].t), yOf(0));
      r.forEach(function (p) { ctx.lineTo(xOf(p.t), yOf(p[key])); });
      ctx.lineTo(xOf(r[r.length - 1].t), yOf(0));
      ctx.closePath();
      ctx.fillStyle = color; ctx.globalAlpha = 0.12; ctx.fill(); ctx.globalAlpha = 1;
      ctx.beginPath();
      r.forEach(function (p, i) { i ? ctx.lineTo(xOf(p.t), yOf(p[key])) : ctx.moveTo(xOf(p.t), yOf(p[key])); });
      ctx.strokeStyle = color; ctx.lineWidth = 2; ctx.lineJoin = "round"; ctx.stroke();
    });
    // Hover: a crosshair at the nearest step and its average and peak in the caption.
    var hover = chartHover[key];
    var shown = data[data.length - 1];
    if (hover !== undefined && hover !== null) {
      var t = t0 + ((hover - left) / w) * span;
      shown = data.reduce(function (best, p) { return Math.abs(p.t - t) < Math.abs(best.t - t) ? p : best; }, data[0]);
      var hx = Math.round(xOf(shown.t)) + 0.5;
      ctx.strokeStyle = muted; ctx.lineWidth = 1; ctx.globalAlpha = 0.6;
      ctx.beginPath(); ctx.moveTo(hx, top); ctx.lineTo(hx, top + h); ctx.stroke(); ctx.globalAlpha = 1;
      ctx.beginPath(); ctx.arc(hx, yOf(shown[key]), 4, 0, 2 * Math.PI);
      ctx.fillStyle = color; ctx.fill();
      ctx.lineWidth = 2; ctx.strokeStyle = style.getPropertyValue("--panel").trim() || "#fff"; ctx.stroke();
    }
    if (readout) {
      var peak = shown[key + "_max"];
      readout.textContent = (hover !== undefined && hover !== null ? timeLabel(shown.t, true) : "Latest") + ": "
        + Math.round(shown[key]) + "%" + (peak !== null && peak !== undefined && peak > shown[key] + 0.5
          ? " (peak " + Math.round(peak) + "%)" : "");
    }
    if (!canvas.hasAttribute("data-hover")) {
      canvas.setAttribute("data-hover", "1");
      canvas.addEventListener("mousemove", function (ev) {
        var rect = canvas.getBoundingClientRect();
        chartHover[key] = ev.clientX - rect.left;
        drawMetrics();
      });
      canvas.addEventListener("mouseleave", function () { chartHover[key] = null; drawMetrics(); });
    }
  }
  window.addEventListener("resize", function () { drawMetrics(); });
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
  // Firewalls page: the Status column follows each firewall (online/offline and the task it is running, with
  // upgrade progress) without reloading the page, so ticked checkboxes and the open select stay as they are.
  var fleet = document.querySelector("[data-activity-url]");
  if (fleet && window.fetch) {
    var cells = {};
    fleet.querySelectorAll("[data-activity]").forEach(function (td) { cells[td.getAttribute("data-activity")] = td; });
    var ids = Object.keys(cells);
    var refresh = function () {
      if (document.hidden || !ids.length) return;
      fetch(fleet.getAttribute("data-activity-url") + "?ids=" + encodeURIComponent(ids.join(",")),
            { credentials: "same-origin", headers: { Accept: "application/json" } })
        .then(function (r) { return r.ok ? r.json() : null; })
        .then(function (data) {
          if (!data) return;
          Object.keys(data).forEach(function (id) {
            var td = cells[id], a = data[id];
            if (!td) return;
            var badge = td.querySelector(".badge");
            if (badge) { badge.className = "badge s-" + a.status; badge.textContent = a.status; }
            var box = td.querySelector(".activity");
            if (!box) return;
            box.hidden = !a.text;
            box.className = "activity small" + (a.state === "running" ? " running" : a.state === "queued" ? " muted" : "");
            box.textContent = "";
            var text = document.createElement("span");
            text.className = "activity-text";
            text.textContent = a.text || "";
            box.appendChild(text);
            if (a.percent !== null && a.percent !== undefined) {
              var pct = document.createElement("span");
              pct.className = "activity-pct";
              pct.textContent = " " + a.percent + "%";
              box.appendChild(pct);
            }
            if (a.more) {
              var more = document.createElement("span");
              more.className = "activity-more muted";
              more.textContent = " +" + a.more + " queued";
              box.appendChild(more);
            }
          });
        })
        .catch(function () {});
    };
    window.setInterval(refresh, 5000);
  }
  // Logs: narrow the rows already shown to those containing the typed text (no new fetch).
  // Tables with data-paged="10": that many rows a page, a pager under the table, and a search box
  // (data-paged-search="#table-id") that narrows the rows as you type. MAC addresses match in any notation.
  // The page and search are kept for the session, since a firewall's page reloads itself when it changes.
  function squash(text) { return text.toLowerCase().replace(/[\s:.\-]/g, ""); }
  function remember(key, value) {
    try {
      if (value === undefined) return JSON.parse(window.sessionStorage.getItem(key) || "null");
      window.sessionStorage.setItem(key, JSON.stringify(value));
    } catch (e) { return null; }
  }
  document.querySelectorAll("table[data-paged]").forEach(function (table) {
    var body = table.tBodies[0];
    if (!body) return;
    var size = parseInt(table.getAttribute("data-paged"), 10) || 10;
    var noun = table.getAttribute("data-paged-noun") || "items";
    var rows = Array.prototype.slice.call(body.rows).filter(function (r) { return !r.hasAttribute("data-empty"); });
    var texts = rows.map(function (r) { var t = r.textContent.toLowerCase(); return { text: t, squashed: squash(t) }; });
    var search = table.id ? document.querySelector('[data-paged-search="#' + table.id + '"]') : null;
    var key = "paged:" + location.pathname + ":" + (table.id || "");
    var saved = remember(key) || {};
    var page = saved.page || 0;
    if (search && saved.q !== undefined && saved.q !== null && !search.value) search.value = saved.q;
    var none = document.createElement("tr");
    none.innerHTML = '<td class="muted" colspan="' + ((rows[0] && rows[0].cells.length) || 1) + '">Nothing matches.</td>';
    none.hidden = true;
    body.appendChild(none);
    var pager = document.createElement("nav");
    pager.className = "pager";
    pager.setAttribute("aria-label", "Pages");
    table.parentNode.insertBefore(pager, table.nextSibling);
    function render() {
      var q = search ? search.value.trim().toLowerCase() : "";
      var sq = squash(q);
      var shown = [];
      rows.forEach(function (r, i) {
        var hit = !q || texts[i].text.indexOf(q) !== -1 || (sq.length > 1 && texts[i].squashed.indexOf(sq) !== -1);
        if (hit) shown.push(r);
        r.hidden = true;
      });
      var pages = Math.max(1, Math.ceil(shown.length / size));
      page = Math.min(Math.max(page, 0), pages - 1);
      shown.slice(page * size, page * size + size).forEach(function (r) { r.hidden = false; });
      none.hidden = !(q && rows.length && !shown.length);
      remember(key, { page: page, q: search ? search.value : null });
      if (shown.length <= size) {
        pager.innerHTML = rows.length > size || q ? '<span class="muted small">' + shown.length + " of " + rows.length + " " + noun + "</span>" : "";
        return;
      }
      pager.innerHTML = '<button type="button" class="small" data-go="-1"' + (page ? "" : " disabled") + '>‹ Previous</button>'
        + '<span class="small">Page ' + (page + 1) + " of " + pages + ' <span class="muted">· ' + shown.length
        + (shown.length !== rows.length ? " of " + rows.length : "") + " " + noun + "</span></span>"
        + '<button type="button" class="small" data-go="1"' + (page < pages - 1 ? "" : " disabled") + ">Next ›</button>";
    }
    pager.addEventListener("click", function (ev) {
      var go = ev.target.getAttribute && ev.target.getAttribute("data-go");
      if (go) { page += parseInt(go, 10); render(); }
    });
    if (search) search.addEventListener("input", function () { page = 0; render(); });
    render();
  });
  // Collapsible cards (<details data-remember="name">): open or closed as last left in this browser;
  // opened anyway when the address points into them (#backups).
  document.querySelectorAll("details[data-remember]").forEach(function (box) {
    var key = "open:" + box.getAttribute("data-remember");
    try {
      var saved = window.localStorage.getItem(key);
      if (saved !== null) box.open = saved === "1";
    } catch (e) { /* storage blocked: keep the default */ }
    if (location.hash && box.id && location.hash === "#" + box.id) box.open = true;
    box.addEventListener("toggle", function () {
      try { window.localStorage.setItem(key, box.open ? "1" : "0"); } catch (e) { /* ignore */ }
    });
  });
  document.querySelectorAll("[data-filter-rows]").forEach(function (input) {
    var body = document.querySelector(input.getAttribute("data-filter-rows"));
    if (!body) return;
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      body.querySelectorAll("tr").forEach(function (row) {
        row.hidden = q !== "" && row.textContent.toLowerCase().indexOf(q) === -1;
      });
    });
  });
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
