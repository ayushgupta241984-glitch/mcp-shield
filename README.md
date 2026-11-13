# mcp-shield

`mcp-shield` is a transparent CLI security proxy for [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) servers that communicate over stdio JSON-RPC.

It wraps an MCP server process, intercepts `tools/call` requests, evaluates them against a security rule engine, and blocks or prompts before forwarding risky actions.

## Features

- **Transparent stdio proxy**: spawns and wraps any MCP server command
- **JSON-RPC interception**: inspects inbound/outbound stdio messages (focuses on `tools/call`)
- **Risk tiers**: `SAFE`, `WARN`, `BLOCKED`
- **Security rule engine**:
  - **Destructive shell command blocker**: `rm -rf`, `mkfs`, `dd if=`, fork bombs, `curl|wget ... | sh`, reverse shells (`nc -e`, `/dev/tcp/`, `bash -i >&`), background daemons (`nohup`, `disown`)
  - **Credential & secret exfiltration guard**: `.env`, `~/.ssh/*`, `~/.aws/*`, `~/.kube/*`, `id_rsa`, `id_ed25519`, `credentials.json`, keychain files, `.git/config`
  - **Indirect prompt injection heuristics**: common injection phrases and invisible/zero-width/bidi Unicode characters
  - **Data exfiltration defense**: detects network-like calls with token/base64-like encoded data in URL query parameters
- **Interactive enforcement** (on `WARN`): terminal bell + prompt via `/dev/tty` (or `CONIN$` on Windows)
- **Configurable policy** via optional `mcp-shield.toml`
- **Rich terminal logs to stderr** (stdout remains clean for JSON-RPC)

## Installation

```bash
pip install .
# or for development
pip install -e .[dev]
```

> `mcp-shield` aims to be minimal-dependency in runtime usage; it currently uses `rich` for terminal UI rendering.

## Usage

Wrap any MCP server command after `--`:

```bash
mcp-shield wrap -- npx -y @modelcontextprotocol/server-filesystem /Users/user/Desktop
```

`mcp-shield` will:
- print a header and tool-call logs to **stderr**
- forward JSON-RPC messages over **stdin/stdout**
- pause for confirmation on `WARN` actions
- return a JSON-RPC error for blocked/rejected actions:

```json
{"jsonrpc":"2.0","error":{"code":-32000,"message":"Blocked by mcp-shield security policy"},"id":1}
```

### Integrating with Claude Desktop

Add `mcp-shield` directly into your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "mcp-shield",
      "args": [
        "wrap",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/Users/username/Desktop"
      ]
    }
  }
}
```

`mcp-shield` will quietly monitor all tool calls and block destructive actions or credential leaks without breaking Claude's JSON-RPC pipe.

## Configuration (`mcp-shield.toml`)

Place an optional `mcp-shield.toml` in the working directory:

```toml
[mcp-shield]
# Additional command substrings/pattern text to block (matched case-insensitively)
blocked_commands = ["terraform destroy", "shutdown -h"]

# Paths under which sensitive-path findings are allowed (resolved)
allowed_directories = ["./safe-secrets-fixtures"]

# Whitelist matched findings by rule category or reason substring
# Categories: shell, credential, injection, exfiltration, config
whitelist_rules = ["rule:injection", "pattern:credentials.json fixture"]
```

Notes:
- Invalid/unreadable config files fail open to defaults (the proxy keeps running).
- `allowed_directories` suppresses sensitive-path findings for paths inside those directories.
- `whitelist_rules` can suppress findings by category (`rule:<category>`) or by substring (`pattern:<text>` or plain substring).

## Project Structure

```text
mcp-shield/
├── mcp_shield/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── engine.py
│   ├── rules.py
│   └── ui.py
├── tests/
│   ├── test_engine.py
│   └── test_proxy.py
├── pyproject.toml
├── README.md
└── LICENSE
```

## Development & Tests

```bash
pytest
```

## Limitations / Security Notes

- This is a **best-effort heuristic** security layer, not a sandbox or complete guarantee.
- It primarily inspects `tools/call` request payloads; other message types are forwarded.
- Prompt-injection and exfiltration detection are pattern/heuristic-based and may produce false positives/negatives.
- For high-assurance environments, combine with OS sandboxing, least-privilege credentials, and audited MCP server configurations.

## License

MIT (see `LICENSE`).
