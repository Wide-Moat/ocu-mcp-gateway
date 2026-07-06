// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

//go:build dockerimage

// Package image holds the container-image keystone test for the ocu-mcp-gatewayd
// daemon. It is gated behind the `dockerimage` build tag so the default
// `go test ./...` (which has no Docker daemon) never runs it; CI and a local
// operator opt in with `go test -tags dockerimage ./test/image/`.
//
// The test asserts BEHAVIOUR of the built image, not the text of the Dockerfile:
// a distroless, non-root final stage; the daemon's own -health-check self-probe;
// and a fail-closed boot that names the missing flag (never a panic, never a
// silent start). A non-distroless base (a shell present, a root user) reds it —
// that is the two-sided keystone neuter.
package image

import (
	"bytes"
	"os/exec"
	"strings"
	"testing"
)

// imageTag is the throwaway local tag the test builds and inspects. It never
// leaves the build host.
const imageTag = "ocu-mcp-gateway-imagetest:keystone"

// repoRoot is two directories up from this test file (test/image → repo root),
// the build context that holds the Dockerfile and the module.
const repoRoot = "../.."

// buildImage builds the image from the repo Dockerfile once for the suite. A
// build failure (no Dockerfile, a broken stage) fails the test loudly — that is
// the RED signal before the Dockerfile exists.
func buildImage(t *testing.T) {
	t.Helper()
	cmd := exec.Command("docker", "build", "-t", imageTag, repoRoot)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker build failed (is there a Dockerfile at the repo root?): %v\n%s", err, out.String())
	}
}

// runInImage runs the built image with the given daemon args and returns the
// combined output and the process exit code.
func runInImage(t *testing.T, args ...string) (string, int) {
	t.Helper()
	full := append([]string{"run", "--rm", imageTag}, args...)
	cmd := exec.Command("docker", full...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("docker run %v could not start: %v\n%s", args, err, out.String())
		}
	}
	return out.String(), code
}

// inspect returns a single Go-template field from `docker inspect` of the image.
func inspect(t *testing.T, format string) string {
	t.Helper()
	cmd := exec.Command("docker", "inspect", "-f", format, imageTag)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		t.Fatalf("docker inspect %q failed: %v\n%s", format, err, out.String())
	}
	return strings.TrimSpace(out.String())
}

// TestImageHealthCheckIsReadinessProbe asserts the image's -health-check is a
// READINESS probe, not a bare liveness "ok": run in isolation (no serving daemon
// bound at the probed address) it must exit NON-ZERO, because /healthz is
// unreachable — the honest not-ready verdict a `depends_on: service_healthy` gate
// needs. A liveness-only probe would fake-green here (exit 0 with no daemon at
// all). The distroless image has no shell or curl, so the binary is its own probe
// (mirrors ocu-control). The green path (a live daemon answering 200) is covered
// in-process by cmd/ocu-mcp-gatewayd health-check tests and firsthand in the fleet.
func TestImageHealthCheckIsReadinessProbe(t *testing.T) {
	buildImage(t)
	// No daemon is serving inside this throwaway container, so the probe's dial to
	// /healthz is refused → a non-zero (unhealthy) exit.
	out, code := runInImage(t, "-health-check", "-listen", "127.0.0.1:8080")
	if code == 0 {
		t.Fatalf("-health-check with no serving daemon exited 0 (fake-green liveness); a readiness probe must exit non-zero when /healthz is unreachable. output:\n%s", out)
	}
	if strings.Contains(strings.ToLower(out), "panic") {
		t.Fatalf("-health-check panicked rather than returning a clean unhealthy verdict:\n%s", out)
	}
}

// TestImageBootFailsClosedNamingMissingFlag asserts that running the daemon with
// NO configuration fails closed — a non-zero exit whose message NAMES the first
// missing required flag (-boot-set). This proves the shipped image never silently
// starts an unconfigured gateway and never panics; it refuses with an operator-
// actionable message (invariant #9).
func TestImageBootFailsClosedNamingMissingFlag(t *testing.T) {
	buildImage(t)
	out, code := runInImage(t) // no args: boot must refuse
	if code == 0 {
		t.Fatalf("daemon with no flags exited 0 (silent start); it must fail closed. output:\n%s", out)
	}
	if strings.Contains(strings.ToLower(out), "panic") {
		t.Fatalf("daemon boot panicked rather than failing closed cleanly:\n%s", out)
	}
	if !strings.Contains(out, "-boot-set") {
		t.Fatalf("fail-closed message does not NAME the missing flag -boot-set (operator-actionable); got:\n%s", out)
	}
	if !strings.Contains(out, "fail-closed") {
		t.Fatalf("fail-closed message does not declare the fail-closed posture; got:\n%s", out)
	}
}

// TestImageRunsAsNonRoot asserts the final image runs as a non-root user. A root
// final stage reds this — half of the keystone neuter (a non-distroless base
// image defaults to root).
func TestImageRunsAsNonRoot(t *testing.T) {
	buildImage(t)
	user := inspect(t, "{{.Config.User}}")
	if user == "" || strings.HasPrefix(user, "root") || user == "0" || strings.HasPrefix(user, "0:") {
		t.Fatalf("image Config.User = %q; the final stage must run as a non-root user (distroless nonroot, uid 65532)", user)
	}
}

// TestImageIsDistrolessNoShell asserts the final stage is distroless: there is no
// shell to exec. Attempting to run `/bin/sh` in the image must fail (the binary
// is not present). A conventional base (debian, alpine) ships a shell and reds
// this — the other half of the keystone neuter.
func TestImageIsDistrolessNoShell(t *testing.T) {
	buildImage(t)
	// Override the entrypoint to try to launch a shell; distroless has none.
	cmd := exec.Command("docker", "run", "--rm", "--entrypoint", "/bin/sh", imageTag, "-c", "echo reached-a-shell")
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	if err == nil || strings.Contains(out.String(), "reached-a-shell") {
		t.Fatalf("a shell was reachable in the image (not distroless); output:\n%s", out.String())
	}
}
