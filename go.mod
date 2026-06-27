// Module path reflects this public repo's MCP-gateway module (component-01).
// Each dependency arrives through the architecture repo's dependency policy
// (license gate + supply-chain gate); see NOTICE for third-party license
// notices.
//
// The gateway sits in front of the control plane: it terminates inbound MCP
// tool-calls (F1), validates them against the OCU constraint profile, and
// forwards a session request to the Control/operator API (F5) under its own
// service identity — never the caller's credential. It runs no agent loop and
// holds no state that outlives a request.
module github.com/Wide-Moat/ocu-mcp-gateway

// Minor-version directive (not a pinned patch): the sibling ocu-control pins
// 1.26.4, but a bare 1.26 lets any 1.26.x toolchain build locally without a
// forced toolchain download. CI pins the exact toolchain in the workflow.
go 1.26

require (
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	golang.org/x/text v0.14.0 // indirect
	pgregory.net/rapid v1.3.0 // indirect
)
