<!--
SPDX-License-Identifier: FSL-1.1-Apache-2.0
Copyright (c) 2025 Open Computer Use Contributors
-->

# ocu-mcp-gateway

The **MCP gateway** (component-01 of the OCU next/v1 architecture): the agent
tool-call ingress that sits **before** the control plane. It authenticates the
MCP caller, validates the tool-call against the OCU constraint profile, and
forwards a session request to the Control/operator API under its **own service
identity** — never the caller's credential. It runs no agent loop, holds no model,
and keeps no state that outlives a request.

## Position

```
 MCP client ──F1──▶ ocu-mcp-gateway ──F5──▶ Control/operator API
 (owns the loop)     (this repo)      │
                                      └──F10──▶ Audit pipeline (OCSF)
```

- **F1** — inbound MCP tool-call from the agent/MCP client (the client owns the
  loop and the model; the gateway terminates the tool-call only).
- **F5** — session-request forward to Control, carrying the gateway's own service
  identity. The caller credential is terminated at ingress and never forwarded.
- **F10** — OCSF audit fan-in (fail-closed, durable-first).

There is **no** gateway→sandbox edge and **no** gateway→operator-ingress edge: the
operator surface (kill-switch / denylist / lifecycle) is unreachable from the
gateway, in code and on the network (see `CONSTITUTION.md` §IV).

## Invariants

The load-bearing security and custody properties are listed in
[`CONSTITUTION.md`](CONSTITUTION.md), each mapped to a named enforcing test and
proven RED-when-neutered. In brief: validate-then-forward (reject pre-buffer),
identity from the transport only, the caller credential never on the forward leg,
no route to the operator surface (code + network), leak-free bounded outbound,
pinned protocol revision, per-caller connection ceiling (refuse not queue),
fail-closed everywhere, and load-before-bind boot.

## Authentication

Caller auth is a **seam** (`internal/auth`) abstracting two shelves of one
decision (ADR-0027, gated on PR #311 to the architecture canon):

- **Minimal shelf** — a static `sk-ocu-` API key, per-caller, 256-bit CSPRNG,
  stored only as salted SHA-256 (never plaintext), validated in-process against
  the Control-owned boot-loaded set with a constant-time compare. The gateway
  never mints keys and never owns a key DB — Control is the single mint point.
- **Full shelf** — the customer-IdP OAuth 2.1 Resource Server flow.

## Build and run

```sh
go build ./...
go test ./...

# Run the daemon (requires the Control-owned boot-set; fails closed without it).
go build -o ocu-mcp-gatewayd ./cmd/ocu-mcp-gatewayd
./ocu-mcp-gatewayd \
  -listen 127.0.0.1:8080 \
  -boot-set /etc/ocu/mcp-keys/boot-set.json \
  -service-identity ocu-mcp-gateway \
  -control-url https://ocu-control:8443
```

## Canon

The contract this component implements lives in the architecture canon
(`Wide-Moat/open-computer-use`), pinned by SHA. What was read and what was
vendored, at which revision, is recorded in [`VENDORED.md`](VENDORED.md). The OCU
constraint profile is vendored byte-identical under
`contracts/mcp/2025-06-18/`.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Merge to `main` is owner-gated; push and
open-PR are delegated. Every change that touches an invariant must update its
enforcing test in the same commit (`CONSTITUTION.md`).

## License

`FSL-1.1-Apache-2.0`. See [`LICENSE`](LICENSE), [`LICENSE-APACHE`](LICENSE-APACHE),
[`LICENSE-MIT`](LICENSE-MIT), and [`NOTICE`](NOTICE).
