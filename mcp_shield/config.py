"""Configuration loading for mcp-shield."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

try:
    import tomllib  # Python 3.11+
except Exception:  # pragma: no cover
    tomllib = None  # type: ignore


@dataclass
class ShieldConfig:
    blocked_commands: list[str] = field(default_factory=list)
    allowed_directories: list[str] = field(default_factory=list)
    whitelist_rules: list[str] = field(default_factory=list)  # e.g. "rule:shell", "rule:credential", "pattern:<substr>"
    config_path: str | None = None

    @classmethod
    def load(cls, directory: str | os.PathLike[str] | None = None) -> "ShieldConfig":
        base = Path(directory or os.getcwd())
        path = base / "mcp-shield.toml"
        if not path.exists():
            return cls()
        if tomllib is None:
            # No TOML parser available (very old Python). Fail open to defaults.
            return cls(config_path=str(path))
        try:
            with path.open("rb") as f:
                data = tomllib.load(f) or {}
        except Exception:
            # Invalid config should not crash the proxy; operate with defaults.
            return cls(config_path=str(path))

        section = data.get("mcp-shield", data)
        if not isinstance(section, dict):
            section = {}

        def _str_list(key: str) -> list[str]:
            val = section.get(key, [])
            if not isinstance(val, list):
                return []
            out: list[str] = []
            for item in val:
                if isinstance(item, str) and item.strip():
                    out.append(item.strip())
            return out

        cfg = cls(
            blocked_commands=_str_list("blocked_commands"),
            allowed_directories=[_normalize_path(p) for p in _str_list("allowed_directories")],
            whitelist_rules=_str_list("whitelist_rules"),
            config_path=str(path),
        )
        return cfg


def _normalize_path(p: str) -> str:
    try:
        return str(Path(p).expanduser().resolve())
    except Exception:
        return os.path.expanduser(p)


def is_path_allowed(path: str, allowed_directories: list[str]) -> bool:
    if not allowed_directories:
        return False
    try:
        target = Path(path).expanduser().resolve()
    except Exception:
        return False
    for root in allowed_directories:
        try:
            r = Path(root).expanduser().resolve()
            if target == r or r in target.parents:
                return True
        except Exception:
            continue
    return False


def is_whitelisted(reason: str, category: str, whitelist_rules: list[str]) -> bool:
    reason_l = (reason or "").lower()
    category_l = (category or "").lower()
    for rule in whitelist_rules:
        r = rule.strip()
        if not r:
            continue
        rl = r.lower()
        if rl == f"rule:{category_l}" or rl == category_l:
            return True
        if rl.startswith("pattern:"):
            pat = rl[len("pattern:"):].strip()
            if pat and pat in reason_l:
                return True
        elif rl in reason_l:
            return True
    return False
