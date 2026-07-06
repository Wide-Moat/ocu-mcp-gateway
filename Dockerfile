# SPDX-License-Identifier: FSL-1.1-Apache-2.0
# Copyright (c) 2025 Open Computer Use Contributors
#
# Multi-stage build for the ocu-mcp-gatewayd MCP gateway daemon (component-01).
# The builder stage cross-compiles a static binary with the SAME flags the
# release pipeline uses (CGO_ENABLED=0, -trimpath, -s -w), so the container
# binary and the released binary are build-identical. The final stage is
# distroless static running as nonroot: no shell, no package manager, no libc —
# the daemon is the only thing in the image. This mirrors the component-02
# (ocu-control) Dockerfile so the fleet has one image posture, not two.
#
# The daemon carries no semver (its revision is the negotiated MCP date string,
# NFR-IC-04), so — unlike control — there is no main.version symbol to stamp and
# no VERSION build-arg / -X ldflag. It writes no local files (the audit sink is a
# network bus, F10; the MCP listener is a TCP socket, not a Unix socket), so there
# is no VOLUME and no writable-mount skeleton to stage.
#
# Both base images are pinned by multi-arch index digest (covers linux/amd64 and
# linux/arm64); bumping a base is an explicit, reviewable diff (vendored-integrity
# + trivy image scan gate on it).

# --- builder: runs on the build host's native platform and cross-compiles for
#     the target (Go needs no emulation to cross-compile), so a multi-arch build
#     never pays the QEMU tax in the compile stage.
FROM --platform=$BUILDPLATFORM golang:1.26.4@sha256:87a41d2539e5671777734e91f467499ed5eafb1fb1f77221dff2744db7a51775 AS build

ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

# Module graph first: the download layer caches independently of source edits.
COPY go.mod go.sum* ./
RUN go mod download

COPY . .

# Static, stripped, reproducible: CGO off (no libc in the distroless final),
# -trimpath (no build-host paths in the binary), -s -w (no symbol/debug tables).
# No -X main.version: the gateway has no semver symbol to stamp (NFR-IC-04).
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w" \
    -o /out/ocu-mcp-gatewayd ./cmd/ocu-mcp-gatewayd

# --- final: distroless static, nonroot (uid 65532), digest-pinned. No shell, no
#     package manager, no libc — the binary is the entire attack surface.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639

LABEL org.opencontainers.image.source="https://github.com/Wide-Moat/ocu-mcp-gateway" \
      org.opencontainers.image.description="Open Computer Use MCP gateway (component-01): one-per-deployment daemon that terminates the sk-ocu- caller key (ADR-0027) and forwards session setup to Control over mTLS" \
      org.opencontainers.image.licenses="FSL-1.1-Apache-2.0"

COPY --from=build /out/ocu-mcp-gatewayd /usr/local/bin/ocu-mcp-gatewayd

USER nonroot:nonroot

# HEALTHCHECK uses the daemon's own -health-check self-probe: it prints "ok" and
# exits 0 when the binary runs. The distroless image has no shell or curl, so the
# daemon binary is its own liveness probe (mirrors ocu-control). A richer
# readiness probe (boot-set loaded) is a follow-up wired to the Sequencer.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/ocu-mcp-gatewayd", "-health-check"]

ENTRYPOINT ["/usr/local/bin/ocu-mcp-gatewayd"]
