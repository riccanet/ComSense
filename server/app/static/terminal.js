/* Remote terminal (templates/terminal.html): a live session over a WebSocket, or the replay of a
   recorded one (asciicast v2). Uses xterm.js from static/vendor/xterm. */
(function () {
  "use strict";
  const el = document.getElementById("terminal");
  if (!el || !window.Terminal) return;
  const live = el.dataset.live === "1";
  const status = document.getElementById("terminal-status");
  const term = new window.Terminal({
    cursorBlink: live,
    disableStdin: !live,
    fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
    fontSize: 14,
    scrollback: 5000,
    theme: { background: "#0b0d10" },
  });
  term.open(el);

  function setStatus(text, cls) {
    if (!status) return;
    status.textContent = text;
    status.className = "terminal-status " + (cls || "muted");
  }

  if (live) connect(); else replay();

  function connect() {
    const fit = new window.FitAddon.FitAddon();
    term.loadAddon(fit);
    fit.fit();
    const proto = location.protocol === "https:" ? "wss:" : "ws:";
    const ws = new WebSocket(proto + "//" + location.host + "/terminal/" + encodeURIComponent(el.dataset.session) + "/ws");
    ws.binaryType = "arraybuffer";
    let ended = false;
    const send = (msg) => { if (ws.readyState === WebSocket.OPEN) ws.send(JSON.stringify(msg)); };

    ws.onopen = () => send({ t: "r", c: term.cols, r: term.rows });
    ws.onmessage = (ev) => {
      if (typeof ev.data !== "string") {
        term.write(new Uint8Array(ev.data));
        return;
      }
      let msg;
      try { msg = JSON.parse(ev.data); } catch (e) { return; }
      if (msg.t !== "s") return;
      if (msg.s === "connected") { setStatus("Connected. Root shell on the firewall; the session is recorded.", "ok"); term.focus(); }
      else if (msg.s === "closed") { ended = true; setStatus(msg.m || "The session ended.", "bad"); }
      else setStatus(msg.m || "");
    };
    ws.onclose = () => {
      term.options.disableStdin = true;
      term.options.cursorBlink = false;
      if (!ended) setStatus("Disconnected. Approve a new session from the firewall's page to connect again.", "bad");
      const btn = document.getElementById("terminal-close");
      if (btn) btn.disabled = true;
    };
    term.onData((d) => send({ t: "i", d: d }));
    term.onResize((size) => send({ t: "r", c: size.cols, r: size.rows }));
    window.addEventListener("resize", () => fit.fit());
    const btn = document.getElementById("terminal-close");
    if (btn) btn.addEventListener("click", () => ws.close());
  }

  function replay() {
    fetch(el.dataset.recording, { credentials: "same-origin" })
      .then((r) => { if (!r.ok) throw new Error("HTTP " + r.status); return r.text(); })
      .then((text) => {
        const lines = text.split("\n").filter((l) => l.trim());
        const head = JSON.parse(lines.shift() || "{}");
        if (head.width && head.height) term.resize(head.width, head.height);
        for (const line of lines) {
          let ev;
          try { ev = JSON.parse(line); } catch (e) { continue; }
          if (ev[1] === "o") term.write(ev[2]);
          else if (ev[1] === "r") {
            const [c, r] = String(ev[2]).split("x").map(Number);
            if (c && r) term.resize(c, r);
          }
        }
      })
      .catch((e) => term.write("Could not load the recording (" + e.message + ").\r\n"));
  }
})();
