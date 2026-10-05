# Security

EffectCraft is a local motion-graphics app for personal use. It is not a hosted service and not a multi-user product. Files, pasted data, expressions, scripts, and automation requests are untrusted input: the engine returns an error instead of crashing.

## Reporting

Describe the version, platform, component, and a minimal reproduction. Leave out tokens, private paths, and project contents. Do not post a working exploit on a public issue; contact the repository owner and ask for a private channel first.

## Desktop use

Starting the app with no `--control` flag and no `EFFECTCRAFT_CONTROL_PORT` does not listen on a port. Menus, tools, and file dialogs behave as before.

## Loopback control

`effectcraft --control <port>` (or `EFFECTCRAFT_CONTROL_PORT`) binds `127.0.0.1` only. Every connection must authenticate before any method runs:

```json
{"id": 1, "method": "auth", "params": {"token": "<64 hex characters>"}}
```

The token is 256 random bits, written as 64 hexadecimal characters. Either hex case is accepted. A missing or wrong token gets `{"ok": false, "error": "authentication required"}` and the connection closes. The reply does not contain the token. No control method is dispatched, including method discovery.

Where the token comes from, first match wins:

- `--control-token-file` or `EFFECTCRAFT_CONTROL_TOKEN_FILE`. A missing file is created (mode `0600` on Unix). The app prints the path, not the token.
- `--control-token` or `EFFECTCRAFT_CONTROL_TOKEN`. The app prints that a supplied token is in use, not the token itself. Prefer a file so the secret stays out of shell history.
- Neither: the app generates a token, does not store it, and prints it once on stderr (`effectcraft: control token: …`). The next launch without a file or env var gets a different token.

Do not commit a token. Do not paste it into a project, a screenshot, or a log you keep.

Budgets on that listener: 16 connections, 1 MiB request lines, 8 MiB replies, and 30 second idle socket timeouts. A request still waits up to 60 seconds for the UI thread. An over-budget reply is an error line; the command may already have finished. A JSON-RPC batch and the `batch` tool stop at 256 steps.

This is a same-machine lock so other users and web pages cannot drive the app. An authenticated client can call the whole control surface. The channel is not encrypted. Do not tunnel or proxy it.

## MCP

Prefer stdio. `effectcraft-cli mcp` does not open a TCP port, does not require a token, and the tools are unchanged.

`effectcraft-cli mcp --bridge` (and any other `--bridge` command) talks to loopback control and sends the same bearer token. It refuses any host that is not loopback, and it does not call a control method until `auth` succeeds. Pass `--control-token`, `--control-token-file`, `EFFECTCRAFT_CONTROL_TOKEN`, or `EFFECTCRAFT_CONTROL_TOKEN_FILE`. The bridge does not invent a token.

Stdio request lines are limited to 1 MiB, and a JSON-RPC batch is limited to 256 messages.

## Scripts

Script file and network access stays default-deny. `File` reads outside the project folder, writes, `Socket`, and `system.callSystem` stay off unless Preferences ▸ Scripting & Expressions ▸ Allow Scripts to Write Files and Access Network is on (`scripting.allowScriptsWriteFiles`, default false). The control token does not turn that preference on. `run_script` over MCP or the control channel uses the same gate.

## Not in this build

There is no per-tool capability list, session expiry, security audit log, or multi-tenant session. Those target a shared service; this app is one person on one machine. Untrusted projects can still use a lot of memory; that is separate from this control lock.
