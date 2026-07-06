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
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/audit"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/boot"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/config"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/forward"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/ingress"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/profile"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/quota"
	"github.com/Wide-Moat/ocu-mcp-gateway/internal/serialize"
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
	version         bool
	healthCheck     bool
	listenAddr      string
	bootSetPath     string
	identity        string
	controlURL      string
	connCeiling     int
	allowedOrigins  originList
	auditBus        string
	auditSink       string
	serializeDepth  int
	deployment      string
	refreshInterval time.Duration

	// F5 guarded-construction knobs (§III): the gateway's own service credential,
	// the deployment provisioning policy, and the mTLS-1.3 client material for the
	// Control dial. The credential and the policy are ALWAYS required (the guarded
	// constructor refuses a nil credential and an inadmissible policy); the mTLS
	// triple is required whenever -control-url is set (NFR-SEC-37).
	serviceCredentialFile string
	provisioningPolicy    string
	controlCA             string
	controlClientCert     string
	controlClientKey      string
}

// originList is a repeatable string flag collecting allowed Origin values for the
// DNS-rebinding guard (-allowed-origin https://app.example.com, repeatable).
type originList []string

func (o *originList) String() string { return fmt.Sprint([]string(*o)) }
func (o *originList) Set(v string) error {
	*o = append(*o, v)
	return nil
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
	fs.StringVar(&o.deployment, "deployment", "", "this gateway's deployment scope (REQUIRED; the boot-set must be homogeneous and equal to it — a foreign-deployment record boot-rejects the whole set, ADR-0027)")
	fs.DurationVar(&o.refreshInterval, "boot-set-refresh", 2*time.Minute, "boot-set re-load interval; a revoked key stops authenticating within this window (must be < the NFR-SEC-04 5-min floor)")
	fs.StringVar(&o.controlURL, "control-url", "", "Control/operator API base URL (F5 forward target)")
	fs.StringVar(&o.serviceCredentialFile, "service-credential-file", "", "path to the gateway's host-side service credential file (the Generic internal token presented on F5, NFR-SEC-26; REQUIRED — a forward is never sent anonymously)")
	fs.StringVar(&o.provisioningPolicy, "provisioning-policy", "", "path to the deployment provisioning-policy JSON (workload trust profile, mount intent, egress policy, resource caps — F5 session provisioning comes strictly from deployment config, CONSTITUTION §III; REQUIRED)")
	fs.StringVar(&o.controlCA, "control-ca", "", "path to the CA bundle verifying Control on the F5 mTLS-1.3 leg (required with -control-url, NFR-SEC-37)")
	fs.StringVar(&o.controlClientCert, "control-client-cert", "", "path to the gateway's F5 mTLS client certificate (required with -control-url)")
	fs.StringVar(&o.controlClientKey, "control-client-key", "", "path to the gateway's F5 mTLS client key (required with -control-url)")
	fs.IntVar(&o.connCeiling, "conn-ceiling", 64, "max concurrent in-flight requests per audience-validated caller (NFR-SEC-53)")
	fs.Var(&o.allowedOrigins, "allowed-origin", "allowed browser Origin for the DNS-rebinding guard (repeatable); originless callers are always allowed")
	fs.StringVar(&o.auditBus, "audit-bus", "", "durable audit-bus endpoint (F10 OCSF fan-in over a network bus; not yet wired — a future follow-up, contract #150)")
	fs.StringVar(&o.auditSink, "audit-sink", "", "durable OCSF audit file (append-only newline-delimited JSON, fsync-before-ack); the fleet-aligned F10 sink. Empty AND empty -audit-bus fails closed on every emit")
	fs.IntVar(&o.serializeDepth, "serialize-max-depth", 64, "max queued tool-calls per session before refusal (NFR-IC-05 per-session serializer; DoS guard on the session key)")
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
		// A readiness probe, not a bare liveness check: dial the daemon's /healthz
		// over the SAME listen address the serving path binds, and exit 0 iff it
		// answers 200 (boot-set loaded AND the listener up). A refused dial, a 503
		// (not-ready), or a timeout is a non-zero exit — the honest red a
		// `depends_on: service_healthy` gate relies on. The probe boots nothing.
		probeCtx, cancel := context.WithTimeout(context.Background(), healthCheckTimeout)
		defer cancel()
		return healthCheckProbe(probeCtx, o.listenAddr)
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
	if o.deployment == "" {
		return errors.New("serve: -deployment is required (the boot-set deployment guard cannot be disabled; a foreign-deployment set must boot-reject, ADR-0027; fail-closed)")
	}
	// The refresh interval must be under the NFR-SEC-04 5-min revocation floor: a
	// key Control revoked must stop authenticating within 5 min, so re-loading no
	// more often than every 5 min would miss the window. A non-positive interval
	// would disable refresh (revocation would never converge) — refuse it.
	const revocationFloor = 5 * time.Minute
	if o.refreshInterval <= 0 || o.refreshInterval >= revocationFloor {
		return fmt.Errorf("serve: -boot-set-refresh must be > 0 and < %s (the NFR-SEC-04 revocation floor); got %s", revocationFloor, o.refreshInterval)
	}
	// F5 guarded-construction knobs (§III), validated up front so a misconfigured
	// forward refuses at BOOT with the missing knob named, before any file I/O and
	// long before a listener could bind. The guarded constructor re-checks all of
	// this — these are the operator-friendly early messages, not the enforcement.
	if o.serviceCredentialFile == "" {
		return errors.New("serve: -service-credential-file is required (the gateway presents its OWN service credential on F5 — a forward is never sent anonymously, NFR-SEC-26; fail-closed)")
	}
	if o.provisioningPolicy == "" {
		return errors.New("serve: -provisioning-policy is required (F5 session provisioning comes STRICTLY from deployment config, never a caller body — CONSTITUTION §III; fail-closed)")
	}
	if o.controlURL != "" && (o.controlCA == "" || o.controlClientCert == "" || o.controlClientKey == "") {
		return errors.New("serve: -control-url requires the mTLS material (-control-ca, -control-client-cert, -control-client-key) — the F5 leg is mTLS-1.3 only (NFR-SEC-37); fail-closed")
	}

	// Build the boot-set loader and run the load-before-bind sequencer. The
	// listener is bound ONLY after Load succeeds (invariant #9): an unreadable,
	// schema-invalid, or foreign-deployment boot-set aborts boot before any socket
	// exists.
	loader := &config.FileKeySetLoader{Path: o.bootSetPath, Deployment: o.deployment, Now: time.Now}
	seq, err := boot.NewSequencer(loader)
	if err != nil {
		return fmt.Errorf("serve: build sequencer: %w", err)
	}
	if err := seq.Load(ctx); err != nil {
		return fmt.Errorf("serve: boot-set load failed, not binding listener: %w", err)
	}

	// Build the caller authenticator over the LIVE boot-set (the sequencer's live
	// pointer), so a periodic Refresh that drops a revoked key takes effect on the
	// next resolve without a rebind (NFR-SEC-04). Boot Load already succeeded, so
	// the provider returns a non-nil set now.
	authn, err := auth.NewStaticAuthenticatorLive(seq.LiveKeySet())
	if err != nil {
		return fmt.Errorf("serve: build authenticator: %w", err)
	}

	// Start the boot-set refresh loop: re-load within the NFR-SEC-04 window so a
	// key Control revoked (omitted from the re-rendered set) stops authenticating
	// within ≤5 min. A refresh failure keeps the last-good set (fail-safe, not
	// fail-open and not auth-blanking); it is logged, and convergence resumes on
	// the next successful refresh. The loop stops when ctx is cancelled (shutdown).
	go runRefreshLoop(ctx, seq, o.refreshInterval)

	// Build the constraint-profile validator (base pass + OCU overlay).
	validator, err := profile.NewValidator(profile.NewJSONRPCBaseValidator(), profile.DefaultLimits())
	if err != nil {
		return fmt.Errorf("serve: build validator: %w", err)
	}

	// Build the F5 forwarder through the GUARDED constructor (§III) — the shipped
	// daemon walks the same path the dial guards live on, never around them:
	// the gateway's own service credential (fail-closed at construction if the
	// file is unreadable/empty — NFR-SEC-26), the deployment ProvisioningPolicy
	// (admissibility re-checked by the constructor — ruling A), and the mTLS-1.3
	// dial material whenever a Control endpoint is configured (endpoint without
	// mTLS is a construction refusal — NFR-SEC-37). With no -control-url the
	// forwarder boots without a transport and every Forward fails closed.
	cred, err := forward.NewFileServiceCredential(o.serviceCredentialFile, o.identity)
	if err != nil {
		return fmt.Errorf("serve: build service credential: %w", err)
	}
	provisioning, err := config.LoadProvisioningPolicy(o.provisioningPolicy)
	if err != nil {
		return fmt.Errorf("serve: load provisioning policy: %w", err)
	}
	var dialTLS *tls.Config
	if o.controlURL != "" {
		dialTLS, err = forward.LoadMTLSConfig(o.controlCA, o.controlClientCert, o.controlClientKey)
		if err != nil {
			return fmt.Errorf("serve: load F5 mTLS material: %w", err)
		}
	}
	forwarder, err := forward.NewControlForwarderWithDial(
		forward.ServiceIdentity{Name: o.identity},
		forward.DialConfig{Endpoint: o.controlURL, TLS: dialTLS},
		cred,
		provisioning,
	)
	if err != nil {
		return fmt.Errorf("serve: build forwarder: %w", err)
	}

	// Build the per-caller connection ceiling (invariant #8). The default limit
	// is a conservative per-caller concurrency bound the operator may retune.
	ceiling := quota.NewCeiling(o.connCeiling)

	// Build the Origin policy (DNS-rebinding guard). An empty allowlist admits
	// only originless (non-browser) callers — the safe default for the common MCP
	// (CLI/SDK) caller; browser origins are opted in via -allowed-origin.
	origin := ingress.NewOriginPolicy(o.allowedOrigins)

	// Build the F10 OCSF audit sink and emitter. A configured -audit-sink is the
	// fleet-aligned durable FILE sink: it appends each OCSF envelope as one
	// newline-delimited JSON line and fsyncs BEFORE the emit returns, so a forward
	// cannot ack without a durable record (emit-before-ack, NFR-SEC-03). With no
	// -audit-sink the emitter falls back to the network bus sink (-audit-bus,
	// contract #150), which is not yet wired and fails closed on every emit — so an
	// unconfigured audit surface is a hard deny, never a silent drop. Opening the
	// file sink fails at BOOT if the path is unwritable, so the daemon never boots
	// with a discarded audit trail.
	var sink audit.Sink
	if o.auditSink != "" {
		fileSink, ferr := audit.OpenFileSink(o.auditSink)
		if ferr != nil {
			return fmt.Errorf("serve: open audit file sink: %w", ferr)
		}
		defer func() { _ = fileSink.Close() }()
		sink = fileSink
	} else {
		sink = audit.NewBusSink(o.auditBus)
	}
	emitter, err := audit.NewEmitter(sink)
	if err != nil {
		return fmt.Errorf("serve: build audit emitter: %w", err)
	}

	// Build the per-session tool-call serializer (NFR-IC-05): sequential per
	// session by default, bounded per-session queue (overflow refused, a DoS guard
	// on the caller-supplied session key). The parallel opt-in predicate is nil
	// here — v1 has no skill registry, so every tool serializes; a deployment that
	// grows a parallel-safe tool allow-list injects the predicate here.
	serializer := serialize.NewSerializer(o.serializeDepth, nil)

	// Compose the ingress handler.
	handler, err := ingress.NewHandler(authn, validator, forwarder, ceiling, origin, emitter, serializer)
	if err != nil {
		return fmt.Errorf("serve: build handler: %w", err)
	}

	// Wrap the MCP handler with the unauthenticated /healthz readiness gate. The
	// gate reports ready iff the boot Sequencer is ready (boot-set loaded); serving
	// the gate on the SAME listener means the -health-check probe dials the one
	// address the container binds, so `depends_on: service_healthy` becomes an
	// honest readiness gate (it flips green only once the gateway can accept
	// traffic). Every non-/healthz path still reaches the authenticating MCP
	// handler unchanged.
	mux := ingress.NewReadinessMux(handler, seq.Ready)
	if mux == nil {
		return errors.New("serve: build readiness mux failed (nil handler or predicate; fail-closed)")
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
	srv := ingress.NewServer(ln, mux)
	fmt.Printf("ocu-mcp-gatewayd: serving MCP on %s (service-identity %q)\n", o.listenAddr, o.identity)
	return srv.Serve(ctx)
}

// runRefreshLoop re-loads the boot-set every interval so a revoked key stops
// authenticating within the NFR-SEC-04 window. It returns when ctx is cancelled
// (shutdown). A refresh error keeps the last-good set (fail-safe) and is logged;
// it never blanks auth and never fails the process. The plaintext key is never in
// the boot-set or this log — only the error class is printed.
func runRefreshLoop(ctx context.Context, seq *boot.Sequencer, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := seq.Refresh(ctx); err != nil {
				// Keep the last-good set; surface the failure for the operator. No
				// secret material appears in the error (the boot-set holds only
				// hashes; the error names the cause class, not any key).
				fmt.Fprintf(os.Stderr, "ocu-mcp-gatewayd: boot-set refresh failed (keeping last-good set): %v\n", err)
			}
		}
	}
}
