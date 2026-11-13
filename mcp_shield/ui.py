"""Terminal UI and interactive enforcement for mcp-shield."""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime
from typing import Any

from .engine import BLOCKED, SAFE, WARN

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.text import Text
    RICH_AVAILABLE = True
except Exception:  # pragma: no cover
    Console = None  # type: ignore
    Panel = None  # type: ignore
    Text = None  # type: ignore
    RICH_AVAILABLE = False

# Console writes to stderr so stdout stays clean for JSON-RPC
_console = Console(stderr=True, highlight=False) if RICH_AVAILABLE else None


def print_header(version: str = "0.1.0") -> None:
    title = f"mcp-shield v{version} [ACTIVE]"
    if RICH_AVAILABLE and _console:
        art = Text()
        art.append("🛡️  ", style="bold cyan")
        art.append(title, style="bold white")
        _console.print(Panel.fit(art, border_style="cyan"))
    else:
        sys.stderr.write(f"\n🛡️  {title}\n{'=' * (len(title) + 4)}\n")
        sys.stderr.flush()


def log_tool_call(tool_name: str, args_summary: str, tier: str = SAFE) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    label = "ALLOWED" if tier == SAFE else ("WARN" if tier == WARN else "BLOCKED")
    line = f"[{ts}] [{label}] tool: {tool_name}"
    if args_summary:
        line += f" ({args_summary})"

    if RICH_AVAILABLE and _console:
        style = {"ALLOWED": "green", "WARN": "yellow", "BLOCKED": "red"}.get(label, "white")
        text = Text()
        text.append(f"[{ts}] ", style="dim")
        text.append(f"[{label}]", style=f"bold {style}")
        text.append(f" tool: {tool_name}", style="white")
        if args_summary:
            text.append(f" ({args_summary})", style="dim")
        _console.print(text)
    else:
        sys.stderr.write(line + "\n")
        sys.stderr.flush()


def log_info(message: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if RICH_AVAILABLE and _console:
        _console.print(f"[dim][{ts}][/dim] {message}")
    else:
        sys.stderr.write(f"[{ts}] {message}\n")
        sys.stderr.flush()


def log_error(message: str) -> None:
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    if RICH_AVAILABLE and _console:
        _console.print(f"[dim][{ts}][/dim] [bold red][ERROR][/bold red] {message}")
    else:
        sys.stderr.write(f"[{ts}] [ERROR] {message}\n")
        sys.stderr.flush()


def prompt_warn(reason: str) -> bool:
    """Pause and prompt user on /dev/tty. Returns True to allow, False to deny."""
    # Terminal bell
    try:
        sys.stderr.write("\a")
        sys.stderr.flush()
    except Exception:
        pass

    prompt = f"⚠️  High-Risk Action Detected: {reason}. Allow execution? [y/N]: "
    if RICH_AVAILABLE and _console:
        _console.print(f"[bold yellow]{prompt}[/bold yellow]", end="")
    else:
        sys.stderr.write(prompt)
        sys.stderr.flush()

    # Try to read from controlling terminal directly
    tty_in = None
    tty_out = None
    try:
        if os.name == "nt":
            tty_in = open("CONIN$", "r", encoding="utf-8", errors="ignore")
        else:
            tty_in = open("/dev/tty", "r", encoding="utf-8", errors="ignore")
        answer = tty_in.readline()
    except Exception:
        # Fallback: cannot prompt interactively; deny by default
        if RICH_AVAILABLE and _console:
            _console.print("[dim](no TTY available; defaulting to deny)[/dim]")
        else:
            sys.stderr.write("(no TTY available; defaulting to deny)\n")
            sys.stderr.flush()
        return False
    finally:
        try:
            if tty_in:
                tty_in.close()
        except Exception:
            pass

    ans = (answer or "").strip().lower()
    return ans in ("y", "yes")


def make_blocked_error(msg_id: Any, reason: str | None = None) -> dict[str, Any]:
    message = "Blocked by mcp-shield security policy"
    if reason:
        message = f"{message}: {reason}"
    return {
        "jsonrpc": "2.0",
        "error": {
            "code": -32000,
            "message": message,
        },
        "id": msg_id,
    }


def summarize_args(arguments: Any, max_len: int = 80) -> str:
    try:
        if arguments is None:
            return ""
        if isinstance(arguments, dict):
            parts = []
            for k, v in arguments.items():
                sv = v
                if isinstance(v, str):
                    sv = v if len(v) <= 40 else v[:37] + "..."
                elif isinstance(v, (dict, list)):
                    sv = json.dumps(v, ensure_ascii=False)
                    if len(sv) > 40:
                        sv = sv[:37] + "..."
                parts.append(f"{k}: {sv}")
            s = ", ".join(parts)
        else:
            s = json.dumps(arguments, ensure_ascii=False)
        return s if len(s) <= max_len else s[: max_len - 3] + "..."
    except Exception:
        return ""