"""Remote terminal: relays a root shell on a firewall to an admin's browser.

Starting a session (web/terminal_routes.py): the admin approves it with an authenticator app code,
which creates a TerminalSession and queues an open_terminal task. The firewall picks the task up
within seconds (the agent waits on GET /wait) and starts its terminal helper, which opens a
WebSocket to the agent API (it still only connects out). The browser opens a WebSocket to the web
console. A Relay pairs the two by session id and copies data both ways.

Messages:
  browser -> firewall   text  {"t": "i", "d": "<keystrokes>"}, {"t": "r", "c": cols, "r": rows}
  firewall -> browser   binary terminal output; text {"t": "x", "m": "..."} when the shell ends
  server -> browser     text  {"t": "s", "s": "waiting" | "connected" | "closed", "m": "..."}

Both ends must connect within START_WINDOW of the approval, a session can be joined once, and it
ends after IDLE_LIMIT without input or MAX_DURATION in total. The output is recorded in asciicast
v2 format (data_dir/terminal/<id>.cast) for replay from the device page.

The web console and the agent API run in one process (app/serve.py), so the relays live in memory.
Each end may run on its own event loop (the test clients do), so sends to the other end are
scheduled on that end's loop.
"""
from __future__ import annotations

import asyncio
import codecs
import json
import logging
import threading
import time
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any

from sqlalchemy import select
from starlette.websockets import WebSocket

from ..audit import audit
from ..db import session_factory
from ..models import Device, DeviceStatus, Role, TerminalSession, TerminalStatus, User, aware, utcnow
from ..security import hash_secret

log = logging.getLogger("comsense.terminal")

START_WINDOW = 120  # seconds from approval for the browser and the firewall to connect
IDLE_LIMIT = 15 * 60  # seconds without a keystroke
MAX_DURATION = 2 * 3600
WATCH_INTERVAL = 1.0
RECORDING_LIMIT = 10 * 1024 * 1024
MAX_MESSAGE = 64 * 1024
MIN_SIZE, MAX_COLS, MAX_ROWS = 10, 500, 200


def recording_dir(data_dir: Path) -> Path:
    return data_dir / "terminal"


# --------------------------------------------------------------- admission


def _fresh(ts: TerminalSession) -> bool:
    return (utcnow() - aware(ts.created_at)).total_seconds() <= START_WINDOW


def check_browser(sid: str, uid: Any, pwv: Any, in_session: bool) -> bool:
    """May this browser session join terminal `sid`? Only the approving admin, from the browser
    session that approved it, while the session is fresh and unjoined."""
    if not in_session:
        return False
    with session_factory()() as db:
        user = db.get(User, uid) if uid else None
        if user is None or not user.active or user.role != Role.admin or pwv != user.password_hash[-16:]:
            return False
        ts = db.get(TerminalSession, sid)
        return bool(ts and ts.user_id == user.id and ts.status == TerminalStatus.approved and _fresh(ts))


def check_agent(sid: str, authorization: str) -> str | None:
    """The device id if this device token may join terminal `sid` as the firewall end."""
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    with session_factory()() as db:
        device = db.scalar(select(Device).where(Device.token_hash == hash_secret(token.strip())))
        if device is None or device.status == DeviceStatus.disabled:
            return None
        ts = db.get(TerminalSession, sid)
        if not (ts and ts.device_id == device.id and ts.status == TerminalStatus.approved and _fresh(ts)):
            return None
        device.last_seen_at = utcnow()
        db.commit()
        return device.id


def _mark_connected(sid: str) -> None:
    with session_factory()() as db:
        ts = db.get(TerminalSession, sid)
        if ts is None:
            return
        ts.status = TerminalStatus.connected
        ts.connected_at = utcnow()
        audit(db, ts.username, "terminal.connect", target=ts.device_id, detail=f"session {sid[:8]}")
        db.commit()


def _mark_closed(sid: str, reason: str, bytes_in: int, bytes_out: int) -> None:
    with session_factory()() as db:
        ts = db.get(TerminalSession, sid)
        if ts is None or ts.status == TerminalStatus.closed:
            return
        ts.status = TerminalStatus.closed
        ts.closed_at = utcnow()
        ts.close_reason = reason[:255]
        ts.bytes_in, ts.bytes_out = bytes_in, bytes_out
        audit(db, ts.username, "terminal.close", target=ts.device_id,
              detail=f"session {sid[:8]}: {reason} (in {bytes_in} B, out {bytes_out} B)")
        db.commit()


# ------------------------------------------------------------------- relay

_End = tuple[WebSocket, asyncio.AbstractEventLoop]


async def _on(end: _End, fn: Callable[[WebSocket], Awaitable[Any]]) -> bool:
    """Run fn(websocket) on the loop that owns that websocket. False if it failed (gone)."""
    ws, loop = end
    try:
        if loop is asyncio.get_running_loop():
            await fn(ws)
        else:
            await asyncio.wrap_future(asyncio.run_coroutine_threadsafe(fn(ws), loop))
        return True
    except Exception:  # noqa: BLE001 - the peer went away; the session is ending
        return False


class Recording:
    """asciicast v2: a JSON header line, then [seconds, "o" | "r", data] lines."""

    def __init__(self, path: Path, cols: int, rows: int):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.start = time.monotonic()
        self.size = 0
        self.full = False
        self.decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self.fh = path.open("w", encoding="utf-8")
        self._write({"version": 2, "width": cols, "height": rows, "timestamp": int(time.time())})

    def _write(self, item: Any) -> None:
        line = json.dumps(item, ensure_ascii=False) + "\n"
        self.size += len(line.encode())
        self.fh.write(line)
        self.fh.flush()

    def event(self, kind: str, data: str) -> None:
        if self.full or self.fh.closed:
            return
        if self.size > RECORDING_LIMIT:
            self.full = True
            data, kind = "\r\n[ComSense: recording limit reached; the rest of this session is not recorded]\r\n", "o"
        self._write([round(time.monotonic() - self.start, 3), kind, data])

    def output(self, data: bytes) -> None:
        text = self.decoder.decode(data)
        if text:
            self.event("o", text)

    def close(self) -> None:
        if not self.fh.closed:
            self.fh.close()


class Relay:
    def __init__(self, sid: str, recording_path: Path):
        self.sid = sid
        self.recording_path = recording_path
        self.browser: _End | None = None
        self.agent: _End | None = None
        self.size = (80, 24)
        self.created = time.monotonic()
        self.connected_at: float | None = None
        self.last_input = time.monotonic()
        self.bytes_in = 0
        self.bytes_out = 0
        self.closed = False
        self.recording: Recording | None = None
        self._lock = threading.Lock()

    # -- joining

    def join(self, side: str, ws: WebSocket) -> bool:
        with self._lock:
            if self.closed or getattr(self, side) is not None:
                return False
            setattr(self, side, (ws, asyncio.get_running_loop()))
            return True

    async def _maybe_connect(self) -> None:
        with self._lock:
            if self.connected_at is not None or self.browser is None or self.agent is None or self.closed:
                return
            self.connected_at = time.monotonic()
            self.last_input = self.connected_at
        cols, rows = self.size
        self.recording = Recording(self.recording_path, cols, rows)
        await self.to_agent({"t": "r", "c": cols, "r": rows})
        await self.to_browser({"t": "s", "s": "connected", "m": "Connected."})
        await asyncio.to_thread(_mark_connected, self.sid)

    # -- sending

    async def to_agent(self, message: dict[str, Any]) -> None:
        if self.agent:
            text = json.dumps(message)
            await _on(self.agent, lambda ws: ws.send_text(text))

    async def to_browser(self, message: dict[str, Any]) -> None:
        if self.browser:
            text = json.dumps(message)
            await _on(self.browser, lambda ws: ws.send_text(text))

    # -- ending

    async def shutdown(self, reason: str) -> None:
        with self._lock:
            if self.closed:
                return
            self.closed = True
        _relays.pop(self.sid, None)
        if self.recording:
            self.recording.close()
        log.info("Terminal session %s closed: %s", self.sid[:8], reason)
        await asyncio.to_thread(_mark_closed, self.sid, reason, self.bytes_in, self.bytes_out)
        await self.to_browser({"t": "s", "s": "closed", "m": reason})
        for end in (self.browser, self.agent):
            if end:
                await _on(end, lambda ws: ws.close())

    async def watch(self) -> None:
        while not self.closed:
            await asyncio.sleep(WATCH_INTERVAL)
            now = time.monotonic()
            if self.connected_at is None and now - self.created > START_WINDOW:
                reason = ("The firewall did not connect. Check that it is online and that the agent is 0.2.0 or "
                          "later." if self.agent is None else "The browser did not connect in time.")
            elif self.connected_at is not None and now - self.last_input > IDLE_LIMIT:
                reason = f"Closed after {IDLE_LIMIT // 60} minutes without input."
            elif now - self.created > MAX_DURATION:
                reason = f"Closed after the {MAX_DURATION // 3600} hour limit."
            else:
                continue
            await self.shutdown(reason)


_relays: dict[str, Relay] = {}
_relays_lock = threading.Lock()


def _relay(sid: str, data_dir: Path) -> tuple[Relay, bool]:
    with _relays_lock:
        relay = _relays.get(sid)
        if relay is not None:
            return relay, False
        relay = _relays[sid] = Relay(sid, recording_dir(data_dir) / f"{sid}.cast")
        return relay, True


def active_sessions() -> int:
    return len(_relays)


async def _start(sid: str, side: str, ws: WebSocket, data_dir: Path) -> Relay | None:
    relay, created = _relay(sid, data_dir)
    if not relay.join(side, ws):
        return None
    if created:
        asyncio.get_running_loop().create_task(relay.watch())
    return relay


async def serve_browser(sid: str, ws: WebSocket, data_dir: Path) -> None:
    """The browser end, after the WebSocket was accepted."""
    relay = await _start(sid, "browser", ws, data_dir)
    if relay is None:
        await ws.send_text(json.dumps({"t": "s", "s": "closed", "m": "This session is already open elsewhere."}))
        await ws.close()
        return
    await relay.to_browser({"t": "s", "s": "waiting", "m": "Waiting for the firewall to connect..."})
    reason = "The terminal was closed in the browser."
    try:
        while not relay.closed:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            text = msg.get("text")
            if not text or len(text) > MAX_MESSAGE:
                continue
            try:
                data = json.loads(text)
            except ValueError:
                continue
            if not isinstance(data, dict):
                continue
            if data.get("t") == "i" and isinstance(data.get("d"), str):
                relay.last_input = time.monotonic()
                relay.bytes_in += len(data["d"].encode())
                await relay.to_agent({"t": "i", "d": data["d"]})
            elif data.get("t") == "r":
                try:
                    cols = min(max(int(data.get("c")), MIN_SIZE), MAX_COLS)
                    rows = min(max(int(data.get("r")), MIN_SIZE // 2), MAX_ROWS)
                except (TypeError, ValueError):
                    continue
                relay.size = (cols, rows)
                if relay.recording:
                    relay.recording.event("r", f"{cols}x{rows}")
                await relay.to_agent({"t": "r", "c": cols, "r": rows})
                if relay.connected_at is None:
                    await relay._maybe_connect()
    except Exception:  # noqa: BLE001 - a broken connection ends the session like a disconnect
        pass
    finally:
        await relay.shutdown(reason)


async def serve_agent(sid: str, ws: WebSocket, data_dir: Path) -> None:
    """The firewall end, after the WebSocket was accepted."""
    relay = await _start(sid, "agent", ws, data_dir)
    if relay is None:
        await ws.close()
        return
    reason = "The session ended on the firewall."
    try:
        await relay._maybe_connect()
        while not relay.closed:
            msg = await ws.receive()
            if msg["type"] == "websocket.disconnect":
                break
            chunk = msg.get("bytes")
            if chunk:
                relay.bytes_out += len(chunk)
                if relay.recording:
                    relay.recording.output(chunk)
                if relay.browser and not await _on(relay.browser, lambda b, c=chunk: b.send_bytes(c)):
                    break
            elif msg.get("text"):
                try:
                    data = json.loads(msg["text"])
                except ValueError:
                    continue
                if isinstance(data, dict) and data.get("t") == "x":
                    reason = str(data.get("m") or "The shell exited.")[:200]
                    break
    except Exception:  # noqa: BLE001
        pass
    finally:
        await relay.shutdown(reason)
