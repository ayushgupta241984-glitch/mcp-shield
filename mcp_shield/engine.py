"""Security rule engine for evaluating MCP JSON-RPC tool calls."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import parse_qs, urlparse

from .config import ShieldConfig, is_path_allowed, is_whitelisted
from .rules import (
    BASE64ISH_TOKEN_RE,
    BLOCKED,
    DESTRUCTIVE_COMMAND_PATTERNS,
    INJECTION_PHRASE_PATTERNS,
    NETWORK_ARG_KEYS,
    NETWORK_TOOL_HINTS,
    PATH_ARG_KEYS,
    SAFE,
    SENSITIVE_PATH_PATTERNS,
    SHELL_TOOL_HINTS,
    TEXT_ARG_KEYS,
    URL_WITH_QUERY_RE,
    WARN,
    ZERO_WIDTH_CHARS,
)


@dataclass
class Finding:
    tier: str
    reason: str
    category: str  # shell|credential|injection|exfiltration|config
    evidence: str | None = None


@dataclass
class EvaluationResult:
    tier: str = SAFE
    findings: list[Finding] = field(default_factory=list)

    @property
    def reasons(self) -> list[str]:
        return [f.reason for f in self.findings]

    @property
    def summary(self) -> str:
        if not self.findings:
            return "No issues detected"
        # prioritize highest severity in summary
        ordered = sorted(self.findings, key=lambda f: _tier_rank(f.tier), reverse=True)
        top = ordered[0]
        more = len(ordered) - 1
        return f"{top.tier}: {top.reason}" + (f" (+{more} more)" if more else "")

    def merge(self, finding: Finding) -> None:
        self.findings.append(finding)
        if _tier_rank(finding.tier) > _tier_rank(self.tier):
            self.tier = finding.tier


def _tier_rank(tier: str) -> int:
    return {SAFE: 0, WARN: 1, BLOCKED: 2}.get(tier, 0)


class SecurityEngine:
    def __init__(self, config: ShieldConfig | None = None) -> None:
        self.config = config or ShieldConfig.load()
        self._custom_blocked = [
            (f"custom blocked command: {pat}", re.compile(re.escape(pat), re.IGNORECASE))
            for pat in self.config.blocked_commands
        ]

    def evaluate_tools_call(self, message: dict[str, Any]) -> EvaluationResult:
        """Evaluate a JSON-RPC `tools/call` request message."""
        result = EvaluationResult()
        params = message.get("params") or {}
        if not isinstance(params, dict):
            return result
        tool_name = str(params.get("name") or "")
        arguments = params.get("arguments")
        if arguments is None:
            arguments = {}

        # Walk all values to collect strings and possible paths/urls
        strings = list(_iter_strings(arguments))
        paths = list(_extract_candidate_paths(arguments))
        urls = list(_extract_urls(strings))

        self._check_destructive_shell(tool_name, arguments, strings, result)
        self._check_sensitive_paths(tool_name, arguments, strings, paths, result)
        self._check_prompt_injection(strings, result)
        self._check_exfiltration(tool_name, arguments, strings, urls, result)

        # Apply whitelist filtering (downgrade/drop matched findings)
        filtered: list[Finding] = []
        for f in result.findings:
            if is_whitelisted(f.reason, f.category, self.config.whitelist_rules):
                continue
            # If path is within allowed directories, downgrade credential finding on that path
            if f.category == "credential" and f.evidence and is_path_allowed(f.evidence, self.config.allowed_directories):
                continue
            filtered.append(f)
        result.findings = filtered
        result.tier = SAFE
        for f in filtered:
            if _tier_rank(f.tier) > _tier_rank(result.tier):
                result.tier = f.tier
        return result

    # --- Rule checks ---

    def _check_destructive_shell(self, tool_name: str, arguments: Any, strings: list[str], result: EvaluationResult) -> None:
        # Consider tool name and string payloads that look like shell commands
        candidates: list[str] = []
        tnl = tool_name.lower()
        if any(h in tnl for h in SHELL_TOOL_HINTS):
            # likely shell tool: scan all text-like args
            candidates.extend(strings)
        else:
            # still scan common command keys
            for key, val in _iter_key_values(arguments):
                kl = str(key).lower()
                if kl in {"command", "cmd", "script", "shell"} and isinstance(val, str):
                    candidates.append(val)
        # Also scan any string that contains shell metacharacters heuristically
        for s in strings:
            if s not in candidates and any(tok in s for tok in ("| sh", "| bash", "rm -rf", "mkfs", "dd if=", "/dev/tcp", "nc -e", "nohup", "disown")):
                candidates.append(s)

        for text in candidates:
            for reason, pat in DESTRUCTIVE_COMMAND_PATTERNS + self._custom_blocked:
                if pat.search(text):
                    result.merge(Finding(BLOCKED, reason, "shell", evidence=_truncate(text, 120)))

    def _check_sensitive_paths(self, tool_name: str, arguments: Any, strings: list[str], paths: list[str], result: EvaluationResult) -> None:
        # Evaluate path-like candidates (from keys and raw strings that look like paths)
        candidates = list(paths)
        # also scan all strings for sensitive path fragments
        candidates.extend([s for s in strings if ("/" in s or "\\" in s or s.startswith(".") or s.startswith("~"))])

        seen: set[str] = set()
        for raw in candidates:
            norm = _normalize_for_match(raw)
            if not norm or norm in seen:
                continue
            seen.add(norm)
            for reason, pat in SENSITIVE_PATH_PATTERNS:
                if pat.search(norm) or pat.search(raw):
                    # If explicitly allowed, engine.evaluate will drop it; mark BLOCKED by default
                    result.merge(Finding(BLOCKED, f"sensitive path access: {reason}", "credential", evidence=raw))
                    break

    def _check_prompt_injection(self, strings: list[str], result: EvaluationResult) -> None:
        for text in strings:
            for reason, pat in INJECTION_PHRASE_PATTERNS:
                if pat.search(text):
                    result.merge(Finding(WARN, reason, "injection", evidence=_truncate(text, 120)))
            # Invisible unicode / zero-width characters
            found_zw = [ch for ch in ZERO_WIDTH_CHARS if ch in text]
            if found_zw:
                names = ", ".join(f"U+{ord(ch):04X}" for ch in found_zw[:4])
                result.merge(Finding(WARN, f"invisible/zero-width unicode characters detected ({names})", "injection", evidence=_truncate(repr(text), 120)))
            # Bidi control chars general range
            if re.search(r"[\u202A-\u202E\u2066-\u2069]", text):
                result.merge(Finding(WARN, "bidirectional override characters detected (possible homoglyph/injection)", "injection", evidence=_truncate(repr(text), 120)))

    def _check_exfiltration(self, tool_name: str, arguments: Any, strings: list[str], urls: list[str], result: EvaluationResult) -> None:
        tnl = tool_name.lower()
        networkish = any(h in tnl for h in NETWORK_TOOL_HINTS)
        # also treat presence of URL-bearing arg keys as networkish
        if not networkish:
            for key, _ in _iter_key_values(arguments):
                if str(key).lower() in NETWORK_ARG_KEYS:
                    networkish = True
                    break

        for url in urls:
            try:
                parsed = urlparse(url)
                qs = parse_qs(parsed.query, keep_blank_values=True)
                if not qs:
                    continue
                for k, values in qs.items():
                    for v in values:
                        if not v:
                            continue
                        # flag if value looks like base64/base64url token or long hex-ish secret
                        if BASE64ISH_TOKEN_RE.fullmatch(v) or (len(v) >= 24 and re.fullmatch(r"[A-Fa-f0-9]+", v)):
                            tier = WARN if networkish or "http" in parsed.scheme else WARN
                            result.merge(Finding(tier, "possible data exfiltration: encoded token-like data in URL query parameter", "exfiltration", evidence=_truncate(url, 160)))
                            break
            except Exception:
                continue

        # Heuristic: large base64-looking blobs in arguments for network tools
        if networkish:
            for s in strings:
                if len(s) >= 80 and BASE64ISH_TOKEN_RE.search(s) and ("http://" in s or "https://" in s):
                    result.merge(Finding(WARN, "possible data exfiltration: encoded payload near outbound URL", "exfiltration", evidence=_truncate(s, 120)))


# --- helpers ---

def _iter_strings(obj: Any) -> Iterable[str]:
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_strings(v)


def _iter_key_values(obj: Any) -> Iterable[tuple[Any, Any]]:
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield k, v
            yield from _iter_key_values(v)
    elif isinstance(obj, list):
        for v in obj:
            yield from _iter_key_values(v)


def _extract_candidate_paths(arguments: Any) -> Iterable[str]:
    # from keyed path-like args
    for key, val in _iter_key_values(arguments):
        kl = str(key).lower()
        if kl in PATH_ARG_KEYS and isinstance(val, str):
            yield val
        if kl in TEXT_ARG_KEYS and isinstance(val, str):
            # also consider strings that look like absolute/home/relative paths
            pass
    # from all strings: pick those that look path-like
    for s in _iter_strings(arguments):
        if _looks_like_path(s):
            yield s


def _looks_like_path(s: str) -> bool:
    if not s or len(s) > 1024:
        return False
    if s.startswith(("~/.ssh", "~/.aws", "~/.kube", "/", "\\\\")) or ":\\\\" in s:
        return True
    if s.startswith("./") or s.startswith("../"):
        return True
    if "/.env" in s.replace("\\", "/") or s.endswith(".env"):
        return True
    if "/.git/" in s.replace("\\", "/") or s.replace("\\", "/").endswith("/.git/config"):
        return True
    if "id_rsa" in s or "id_ed25519" in s or "credentials.json" in s or ".keychain" in s:
        return True
    return False


def _normalize_for_match(path: str) -> str:
    p = path.strip().strip('"').strip("'")
    p = os.path.expanduser(p)
    # keep forward-ish form for regex matching
    return p.replace("\\", "/")


def _extract_urls(strings: list[str]) -> list[str]:
    out: list[str] = []
    for s in strings:
        for m in URL_WITH_QUERY_RE.findall(s):
            out.append(m.rstrip(').,;"\''))
    return out


def _truncate(s: str, n: int) -> str:
    s = s.replace("\n", "\\n")
    return s if len(s) <= n else s[: n - 3] + "..."
