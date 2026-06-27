// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors
//
// ocu-mcp-gatewayd — the one-per-deployment MCP gateway daemon (component-01).
//
// main wires SIGINT/SIGTERM into the root context so a host-initiated stop
// unwinds the serve loop cleanly. run() dispatches the -version and -health-check
// informational modes, then runs the load-before-bind boot.
//
// serve() is the composition root. It builds the boot-set loader, runs the boot
// Sequencer — which loads the Control-owned authentication material BEFORE any
// listener binds — constructs the constraint-profile validator, the caller
// authenticator (over the boot-loaded set), and the F5 forwarder under the
// gateway's own service identity, composes the ingress Handler, and binds the MCP
// listener ONLY after boot readiness (so a socket is reachable strictly after the
// gateway can fail-closed-authenticate every request, invariant #9). It then
// serves until the signal-driven shutdown.
//
// Boot is fail-closed throughout: an unreadable boot-set, a nil seam, or a
// missing service identity aborts before any listener binds. There is NO operator
// route mounted here — the gateway reaches no lifecycle/kill-switch operation.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/boot"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/config"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/ingress"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/profile"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/quota"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ocu-mcp-gatewayd:", err)
		os.Exit(1)
	}
}

// options is the parsed command-line/config surface. Each field is a config knob
// the component spec's "Operational concerns" section enumerates: the listen
// address, the boot-set path, the pinned-revision (fixed in code, not retunable),
// the service-identity name, and the Control endpoint.
type options struct {
	version     bool
	healthCheck bool
	listenAddr  string
	bootSetPath string
	identity    string
	controlURL  string
	connCeiling int
}

func parseOptions(args []string) (options, error) {
	fs := flag.NewFlagSet("ocu-mcp-gatewayd", flag.ContinueOnError)
	var o options
	fs.BoolVar(&o.version, "version", false, "print version and exit")
	fs.BoolVar(&o.healthCheck, "health-check", false, "run the health check and exit")
	// Local binds use 127.0.0.1, never 0.0.0.0 (DNS-rebinding / x-ocu-authz).
	fs.StringVar(&o.listenAddr, "listen", "127.0.0.1:8080", "MCP listener bind address")
	fs.StringVar(&o.bootSetPath, "boot-set", "", "path to the Control-owned hashed boot-set file")
	fs.StringVar(&o.identity, "service-identity", "ocu-mcp-gateway", "gateway service identity name presented on F5")
	fs.StringVar(&o.controlURL, "control-url", "", "Control/operator API base URL (F5 forward target)")
	fs.IntVar(&o.connCeiling, "conn-ceiling", 64, "max concurrent in-flight requests per audience-validated caller (NFR-SEC-53)")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	return o, nil
}

func run(args []string) error {
	o, err := parseOptions(args)
	if err != nil {
		return err
	}
	if o.version {
		// The gateway carries no semver; its revision is the negotiated MCP date
		// string. Report that, not a version header (NFR-IC-04).
		fmt.Println("ocu-mcp-gatewayd: MCP revision 2025-06-18")
		return nil
	}
	if o.healthCheck {
		// A minimal liveness check: the binary runs. A richer readiness probe
		// (boot-set loaded) is a follow-up wired to the Sequencer.
		fmt.Println("ok")
		return nil
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return serve(ctx, o)
}

// serve is the composition root: load-before-bind, then serve until shutdown.
func serve(ctx context.Context, o options) error {
	if o.bootSetPath == "" {
		return errors.New("serve: -boot-set is required (the gateway authenticates against the Control-owned boot-set; fail-closed)")
	}

	// Build the boot-set loader and run the load-before-bind sequencer. The
	// listener is bound ONLY after Load succeeds (invariant #9): an unreadable
	// boot-set aborts boot before any socket exists.
	loader := &config.FileKeySetLoader{Path: o.bootSetPath, Now: time.Now}
	seq, err := boot.NewSequencer(loader)
	if err != nil {
		return fmt.Errorf("serve: build sequencer: %w", err)
	}
	if err := seq.Load(ctx); err != nil {
		return fmt.Errorf("serve: boot-set load failed, not binding listener: %w", err)
	}

	// Build the caller authenticator over the boot-loaded set.
	keys, err := seq.KeySet()
	if err != nil {
		return fmt.Errorf("serve: key set unavailable after load: %w", err)
	}
	authn, err := auth.NewStaticAuthenticator(keys)
	if err != nil {
		return fmt.Errorf("serve: build authenticator: %w", err)
	}

	// Build the constraint-profile validator (base pass + OCU overlay).
	validator, err := profile.NewValidator(profile.NewJSONRPCBaseValidator(), profile.DefaultLimits())
	if err != nil {
		return fmt.Errorf("serve: build validator: %w", err)
	}

	// Build the F5 forwarder under the gateway's own service identity.
	forwarder, err := forward.NewControlForwarder(forward.ServiceIdentity{Name: o.identity}, o.controlURL)
	if err != nil {
		return fmt.Errorf("serve: build forwarder: %w", err)
	}

	// Build the per-caller connection ceiling (invariant #8). The default limit
	// is a conservative per-caller concurrency bound the operator may retune.
	ceiling := quota.NewCeiling(o.connCeiling)

	// Compose the ingress handler.
	handler, err := ingress.NewHandler(authn, validator, forwarder, ceiling)
	if err != nil {
		return fmt.Errorf("serve: build handler: %w", err)
	}

	// Bind the listener — strictly AFTER readiness. Local binds use the
	// loopback-or-configured address; production schedules a single instance.
	if !seq.Ready() {
		return errors.New("serve: refusing to bind, sequencer not ready (fail-closed)")
	}
	ln, err := net.Listen("tcp", o.listenAddr)
	if err != nil {
		return fmt.Errorf("serve: bind %q: %w", o.listenAddr, err)
	}
	srv := ingress.NewServer(ln, handler)
	fmt.Printf("ocu-mcp-gatewayd: serving MCP on %s (service-identity %q)\n", o.listenAddr, o.identity)
	return srv.Serve(ctx)
}
