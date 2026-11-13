"""Security rules and pattern definitions for mcp-shield."""

from __future__ import annotations

import re
from typing import Pattern

# Risk tiers
SAFE = "SAFE"
WARN = "WARN"
BLOCKED = "BLOCKED"

# A. Destructive Shell Command Blocker
DESTRUCTIVE_COMMAND_PATTERNS: list[tuple[str, Pattern[str]]] = [
    ("rm -rf destructive delete", re.compile(r"\brm\s+(?:-[^\s]*r[^\s]*f|-[^\s]*f[^\s]*r)\b", re.IGNORECASE)),
    ("rm -rf destructive delete", re.compile(r"\brm\s+-rf\b", re.IGNORECASE)),
    ("filesystem format (mkfs)", re.compile(r"\bmkfs(?:\.[a-z0-9]+)?\b", re.IGNORECASE)),
    ("raw disk write (dd)", re.compile(r"\bdd\s+if=", re.IGNORECASE)),
    ("fork bomb", re.compile(r":\(\)\s*\{\s*:?\s*\|\s*:?\s*&\s*\}\s*;?\s*:")),
    ("pipe to shell", re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sh|bash|zsh|dash|ksh)\b", re.IGNORECASE)),
    ("reverse shell via nc -e", re.compile(r"\bnc(?:at)?\b[^\n]*\s-e\s", re.IGNORECASE)),
    ("reverse shell via /dev/tcp", re.compile(r"/dev/tcp/", re.IGNORECASE)),
    ("reverse shell via bash -i", re.compile(r"\bbash\b[^\n]*\s-i\b[^\n]*>&", re.IGNORECASE)),
    ("background daemon (nohup)", re.compile(r"\bnohup\b", re.IGNORECASE)),
    ("background daemon (disown)", re.compile(r"\bdisown\b", re.IGNORECASE)),
]

# B. Credential & Secret Exfiltration Guard (path patterns)
SENSITIVE_PATH_PATTERNS: list[tuple[str, Pattern[str]]] = [
    (".env file", re.compile(r"(?:^|[\\/])\.env(?:\.[^\\/\s]+)?$", re.IGNORECASE)),
    ("SSH directory/key", re.compile(r"(?:^|[\\/])\.ssh(?:[\\/]|$)", re.IGNORECASE)),
    ("AWS credentials", re.compile(r"(?:^|[\\/])\.aws(?:[\\/]|$)", re.IGNORECASE)),
    ("Kubernetes config", re.compile(r"(?:^|[\\/])\.kube(?:[\\/]|$)", re.IGNORECASE)),
    ("SSH private key (id_rsa)", re.compile(r"(?:^|[\\/])id_rsa(?:\.|$)", re.IGNORECASE)),
    ("SSH private key (id_ed25519)", re.compile(r"(?:^|[\\/])id_ed25519(?:\.|$)", re.IGNORECASE)),
    ("credentials.json", re.compile(r"(?:^|[\\/])credentials\.json$", re.IGNORECASE)),
    ("keychain file", re.compile(r"\.keychain(?:-db)?$", re.IGNORECASE)),
    ("git config", re.compile(r"(?:^|[\\/])\.git[\\/]config$", re.IGNORECASE)),
]

# C. Indirect Prompt Injection Heuristics
INJECTION_PHRASE_PATTERNS: list[tuple[str, Pattern[str]]] = [
    ("prompt injection: ignore previous instructions", re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions", re.IGNORECASE)),
    ("prompt injection: SYSTEM OVERRIDE", re.compile(r"SYSTEM\s+OVERRIDE", re.IGNORECASE)),
    ("prompt injection: maintenance mode", re.compile(r"you\s+are\s+now\s+in\s+maintenance\s+mode", re.IGNORECASE)),
    ("prompt injection: concealment request", re.compile(r"do\s+not\s+mention\s+this\s+to\s+the\s+user", re.IGNORECASE)),
    ("prompt injection: base64 decode and execute", re.compile(r"base64\s+decode\s+and\s+execute", re.IGNORECASE)),
]

# Zero-width / invisible unicode chars often used in homoglyph/invisible attacks
ZERO_WIDTH_CHARS = [
    "\u200b",  # ZERO WIDTH SPACE
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\u2060",  # WORD JOINER
    "\ufeff",  # ZERO WIDTH NO-BREAK SPACE / BOM
    "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",  # bidi overrides
]

# D. Data Exfiltration Defense - suspicious encoded tokens in query params
BASE64ISH_TOKEN_RE = re.compile(r"(?:[A-Za-z0-9+/]{24,}={0,2}|[A-Za-z0-9_-]{24,})")
URL_WITH_QUERY_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

# Names/keys that suggest outbound/network operations
NETWORK_TOOL_HINTS = {
    "fetch", "http", "request", "curl", "wget", "post", "put", "send",
    "upload", "webhook", "browser", "navigate", "open_url",
}
NETWORK_ARG_KEYS = {
    "url", "uri", "endpoint", "href", "link", "target", "webhook",
    "destination", "host", "query", "params",
}
SHELL_TOOL_HINTS = {"bash", "shell", "exec", "execute", "command", "terminal", "run"}
PATH_ARG_KEYS = {"path", "file", "filepath", "filename", "target", "source", "src", "dst", "dest"}
TEXT_ARG_KEYS = {"content", "text", "body", "data", "input", "prompt", "message", "query", "command", "code", "script"}
