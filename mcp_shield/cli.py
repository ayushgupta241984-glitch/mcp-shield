"""CLI entrypoint for mcp-shield."""

from __future__ import annotations

import argparse
import json
import os
import queue
import subprocess
import sys
import threading
from typing import Any, IO

from . import __version__
from .config import ShieldConfig
from .engine import BLOCKED, SAFE, WARN, SecurityEngine
from .ui import log_error, log_info, log_tool_call, make_blocked_error, print_header, prompt_warn, summarize_args


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="mcp-shield", description="Transparent security proxy for MCP servers")
    sub = parser.add_subparsers(dest="command")

    wrap = sub.add_parser("wrap", help="Wrap an MCP server command with mcp-shield")
    wrap.add_argument("cmd", nargs=argparse.REMAINDER, help="Command to run (use: mcp-shield wrap -- <command>)")

    args = parser.parse_args(argv)

    if args.command != "wrap":
        parser.print_help(sys.stderr)
        return 2

    cmd = list(args.cmd or [])
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        sys.stderr.write("Error: no MCP server command provided. Usage: mcp-shield wrap -- <command>\n")
        return 2

    return run_wrap(cmd)


def run_wrap(cmd: list[str]) -> int:
    config = ShieldConfig.load(os.getcwd())
    engine = SecurityEngine(config)
    print_header(__version__)
    if config.config_path:
        log_info(f"Loaded config: {config.config_path}")
    log_info(f"Launching MCP server: {' '.join(cmd)}")

    try:
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=sys.stderr,  # pass through server stderr
            bufsize=0,
        )
    except Exception as e:
        log_error(f"Failed to start MCP server: {e}")
        return 1

    assert proc.stdin is not None
    assert proc.stdout is not None

    # Queues of parsed JSON messages
    client_to_proxy: "queue.Queue[dict[str, Any] | None]" = queue.Queue()
    server_to_proxy: "queue.Queue[dict[str, Any] | None]" = queue.Queue()

    t_in = threading.Thread(target=_reader_thread, args=(sys.stdin.buffer, client_to_proxy, "client"), daemon=True)
    t_out = threading.Thread(target=_reader_thread, args=(proc.stdout, server_to_proxy, "server"), daemon=True)
    t_in.start()
    t_out.start()

    client_open = True
    server_open = True

    try:
        while client_open or server_open:
            # Prefer draining server responses to avoid deadlocks
            progressed = False

            # Handle server -> client messages
            while True:
                try:
                    msg = server_to_proxy.get_nowait()
                except queue.Empty:
                    break
                progressed = True
                if msg is None:
                    server_open = False
                    break
                _write_message(sys.stdout.buffer, msg)

            # Handle client -> server messages (with interception)
            while True:
                try:
                    msg = client_to_proxy.get_nowait()
                except queue.Empty:
                    break
                progressed = True
                if msg is None:
                    client_open = False
                    try:
                        proc.stdin.close()
                    except Exception:
                        pass
                    break
                _handle_client_message(msg, engine, proc.stdin)

            if not progressed:
                # Block briefly waiting for any side
                try:
                    msg = server_to_proxy.get(timeout=0.05)
                    if msg is None:
                        server_open = False
                    else:
                        _write_message(sys.stdout.buffer, msg)
                except queue.Empty:
                    pass

            # If server exited, drain remaining then stop
            if proc.poll() is not None and server_to_proxy.empty():
                server_open = False
                # Drain any last client messages? forward if possible
                if not client_open:
                    break
    except KeyboardInterrupt:
        pass
    finally:
        try:
            if proc.poll() is None:
                proc.terminate()
        except Exception:
            pass
        try:
            proc.wait(timeout=2)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    return proc.returncode or 0


def _handle_client_message(msg: dict[str, Any], engine: SecurityEngine, server_stdin: IO[bytes]) -> None:
    method = msg.get("method")
    msg_id = msg.get("id")

    # Only gate tools/call requests; pass through everything else
    if method == "tools/call" and isinstance(msg.get("params"), dict):
        tool_name = str(msg["params"].get("name") or "<unknown>")
        args = msg["params"].get("arguments")
        summary = summarize_args(args)

        result = engine.evaluate_tools_call(msg)
        if result.tier == SAFE:
            log_tool_call(tool_name, summary, SAFE)
            _write_message(server_stdin, msg)
            return

        if result.tier == WARN:
            log_tool_call(tool_name, summary, WARN)
            allowed = prompt_warn(result.summary)
            if allowed:
                log_info(f"User allowed: {tool_name}")
                _write_message(server_stdin, msg)
            else:
                log_info(f"User denied: {tool_name}")
                _write_message(sys.stdout.buffer, make_blocked_error(msg_id, result.summary))
            return

        # BLOCKED
        log_tool_call(tool_name, summary, BLOCKED)
        _write_message(sys.stdout.buffer, make_blocked_error(msg_id, result.summary))
        return

    # Non-tool-call message: forward untouched
    _write_message(server_stdin, msg)


# --- JSON-RPC framing (line-delimited JSON, tolerant) ---

def _reader_thread(stream: IO[bytes], out_q: "queue.Queue[dict[str, Any] | None]", label: str) -> None:
    buf = b""
    try:
        while True:
            chunk = stream.read(4096)
            if not chunk:
                break
            buf += chunk
            # Try to parse newline-delimited JSON messages
            while True:
                if b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    msg = _try_parse_json(line)
                    if msg is not None:
                        out_q.put(msg)
                    else:
                        # Not parseable as a single JSON message; might be part of other framing or noise
                        # Try to salvage by treating as raw? For proxy correctness, drop unparsable lines.
                        _log_parse_drop(label, line)
                    continue
                # No newline: try to parse whole buffer as a complete JSON object (some transports)
                stripped = buf.strip()
                if not stripped:
                    buf = b""
                    break
                if stripped.startswith(b"{") or stripped.startswith(b"["):
                    try:
                        # Attempt parse; only accept if buffer is valid JSON as-is
                        msg = json.loads(stripped.decode("utf-8"))
                        if isinstance(msg, dict):
                            out_q.put(msg)
                            buf = b""
                    except Exception:
                        pass
                break
        # flush remainder
        if buf.strip():
            msg = _try_parse_json(buf)
            if msg is not None:
                out_q.put(msg)
    except Exception as e:
        try:
            log_error(f"Reader error ({label}): {e}")
        except Exception:
            pass
    finally:
        out_q.put(None)


def _try_parse_json(data: bytes) -> dict[str, Any] | None:
    try:
        s = data.decode("utf-8").strip()
        if not s:
            return None
        obj = json.loads(s)
        if isinstance(obj, dict):
            return obj
        # Batch requests not expected for tools/call interception; ignore for now
        return None
    except Exception:
        return None


def _write_message(stream: IO[bytes], msg: dict[str, Any]) -> None:
    try:
        data = (json.dumps(msg, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
        stream.write(data)
        stream.flush()
    except Exception as e:
        try:
            log_error(f"Failed to write message: {e}")
        except Exception:
            pass


def _log_parse_drop(label: str, line: bytes) -> None:
    # Avoid spamming; only log if there's meaningful content
    try:
        s = line.decode("utf-8", errors="ignore").strip()
        if s:
            log_info(f"Dropped unparsable {label} line ({len(s)} chars)")
    except Exception:
        pass


if __name__ == "__main__":
    raise SystemExit(main())