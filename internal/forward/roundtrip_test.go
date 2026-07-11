// SPDX-License-Identifier: FSL-1.1-Apache-2.0
// Copyright (c) 2025 Open Computer Use Contributors

package forward

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Wide-Moat/ocu-mcp-gateway/internal/auth"
)

// timeNowMinusHour / timeNowPlusHour are the leaf validity window bounds. They are
// tiny wrappers so the cert templates read cleanly; the package under test forbids
// no clock in tests (only production code reads no clock directly).
func timeNowMinusHour() time.Time { return time.Now().Add(-time.Hour) }
func timeNowPlusHour() time.Time  { return time.Now().Add(time.Hour) }

// loopbackIPs is the IP-SAN set the httptest loopback server leaf carries so the
// client verifies the server cert against 127.0.0.1 / ::1.
func loopbackIPs() []net.IP { return []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback} }

// mustParse parses a DER certificate for the tls.Certificate.Leaf field.
func mustParse(t *testing.T, der []byte) *x509.Certificate {
	t.Helper()
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf: %v", err)
	}
	return c
}

// mTLSTestPKI is an ephemeral CA plus a server and a client leaf, all CA-signed,
// for a live mTLS round-trip test. No mock material: the server verifies the
// client chain and the client verifies the server chain against the SAME CA, so
// the test exercises the real handshake the shipped dial performs. It mirrors the
// minimal-shelf self-signed-CA substrate (§8).
type mTLSTestPKI struct {
	caPool     *x509.CertPool
	serverCert tls.Certificate
	clientCert tls.Certificate
}

// newMTLSTestPKI builds the ephemeral CA and the two CA-signed leaves (server SAN
// "control.local"/127.0.0.1, client CN "ocu-mcp-gateway"). It is the transport
// substrate for the live round-trip: the gateway's f.tlsConfig presents the
// client leaf and trusts the CA; the httptest server presents the server leaf and
// requires+verifies the client leaf.
func newMTLSTestPKI(t *testing.T) *mTLSTestPKI {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen CA key: %v", err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ocu-test-ca"},
		NotBefore:             timeNowMinusHour(),
		NotAfter:              timeNowPlusHour(),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA cert: %v", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA cert: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	serverCert := signLeaf(t, caCert, caKey, big.NewInt(2), "control.local", true)
	clientCert := signLeaf(t, caCert, caKey, big.NewInt(3), "ocu-mcp-gateway", false)

	return &mTLSTestPKI{caPool: pool, serverCert: serverCert, clientCert: clientCert}
}

// signLeaf issues one CA-signed leaf. A server leaf carries the DNS SAN and the
// serverAuth EKU (plus 127.0.0.1 so httptest's loopback listener verifies); a
// client leaf carries the clientAuth EKU and a CN identity.
func signLeaf(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey, serial *big.Int, name string, server bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen leaf key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    timeNowMinusHour(),
		NotAfter:     timeNowPlusHour(),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if server {
		tmpl.DNSNames = []string{name}
		tmpl.IPAddresses = loopbackIPs()
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, &key.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf %q: %v", name, err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: mustParse(t, der)}
}

// clientTLSConfig is the gateway-side mTLS config: presents the client leaf and
// trusts the CA, TLS 1.3 floor. It is exactly the shape LoadMTLSConfig produces,
// built here from the in-memory PKI so the test needs no PEM files.
func (p *mTLSTestPKI) clientTLSConfig() *tls.Config {
	return &tls.Config{
		RootCAs:      p.caPool,
		Certificates: []tls.Certificate{p.clientCert},
		MinVersion:   tls.VersionTLS13,
	}
}

// serverTLSConfig is the control-side mTLS config: presents the server leaf and
// requires+verifies the client leaf against the CA — the RequireAndVerifyClientCert
// posture the real control gateway-ingress uses.
func (p *mTLSTestPKI) serverTLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{p.serverCert},
		ClientCAs:    p.caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS13,
	}
}

// controlCreateBody mirrors ocu-control's gateway-ingress createBody (serve.go:300):
// the fields the JSON create wire carries, decoded with DisallowUnknownFields on
// the control side. control accepts {session_hint, image, mount_intent,
// mount_intents, egress_policy} and NO control_pub_key (that field was refused on
// the live control — DisallowUnknownFields 400 — and does not exist in
// createBody). The gateway emits the plural mount_intents list (the ADR-0029
// two-mount layout); the singular stays only as control's accepted legacy input.
type controlCreateBody struct {
	SessionHint  string             `json:"session_hint"`
	Image        string             `json:"image"`
	MountIntent  *controlMountBody  `json:"mount_intent"`
	MountIntents []controlMountBody `json:"mount_intents"`
	EgressPolicy *controlEgressBody `json:"egress_policy"`
}

// controlMountBody / controlEgressBody mirror control's mountIntentBody /
// egressPolicyBody field names exactly (serve.go).
type controlMountBody struct {
	Destination    string `json:"destination"`
	FilesystemID   string `json:"filesystem_id"`
	MemoryStoreID  string `json:"memory_store_id"`
	ReadOnly       bool   `json:"read_only"`
	CacheDurationS uint32 `json:"cache_duration_s"`
}

type controlEgressBody struct {
	DefaultDeny     bool   `json:"default_deny"`
	AllowedUpstream string `json:"allowed_upstream"`
	FilesystemID    string `json:"filesystem_id"`
}

// controlSessionResponse mirrors ocu-control's sessionResponse: the host-derived
// key and the numeric lifecycle state, and nothing else.
type controlSessionResponse struct {
	Key   string `json:"key"`
	State int    `json:"state"`
}

// TestForwardLiveRoundTrip is the F5 keystone: the gateway performs a LIVE create
// over mTLS against a control-shaped httptest server and maps the reply. It proves
// the real wire, not a stub: a JSON POST to /v1alpha/sessions carrying EXACTLY
// {session_hint, image, mount_intent, egress_policy} (mount/egress projected from
// the deployment provisioning, NO control_pub_key) over a verified mTLS handshake,
// the service credential presented, and the 201 {key,state} reply mapped into a
// SessionResponse. The control-mock decodes with DisallowUnknownFields, so a
// control_pub_key or any over-rich field reds the test — pinning the wire to what
// the live control actually accepts.
func TestForwardLiveRoundTrip(t *testing.T) {
	pki := newMTLSTestPKI(t)

	var gotPath, gotMethod, gotCT string
	var gotBody controlCreateBody
	var sawClientCert bool
	var decodeErr error

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		gotCT = r.Header.Get("Content-Type")
		sawClientCert = r.TLS != nil && len(r.TLS.PeerCertificates) > 0
		// The control side decodes with DisallowUnknownFields: an extra field is a
		// 400. Decode the same way so an over-rich body fails the test loudly.
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		decodeErr = dec.Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(controlSessionResponse{Key: "sess-host-derived-key", State: 2})
	}))
	srv.TLS = pki.serverTLSConfig()
	srv.StartTLS()
	defer srv.Close()

	f, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "ocu-mcp-gateway"},
		DialConfig{Endpoint: srv.URL, TLS: pki.clientTLSConfig()},
		staticCred{token: "service-tok", principal: "ocu-mcp-gateway"},
		validProvisioning(),
	)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}

	resp, err := f.Forward(context.Background(), SessionRequest{
		Principal: auth.Caller{KeyID: "k1", Tenant: "tenant-a"},
		ToolCall:  ToolCall{Name: "run", Arguments: []byte(`{}`)},
	})
	if err != nil {
		t.Fatalf("live forward must succeed over mTLS, got %v", err)
	}

	// The wire the gateway actually sent.
	if gotMethod != http.MethodPost {
		t.Errorf("F5 create must be POST, got %s", gotMethod)
	}
	if gotPath != "/v1alpha/sessions" {
		t.Errorf("F5 create must POST /v1alpha/sessions, got %s", gotPath)
	}
	if !sawClientCert {
		t.Error("the forward must present the gateway client certificate (mTLS)")
	}
	if decodeErr != nil {
		t.Errorf("control decodes DisallowUnknownFields; the gateway sent an over-rich or malformed body: %v", decodeErr)
	}
	if !strings.Contains(gotCT, "application/json") {
		t.Errorf("F5 create must send application/json, got %q", gotCT)
	}
	// session_hint is the caller Tenant (the only caller-influenced field, a hint).
	if gotBody.SessionHint != "tenant-a" {
		t.Errorf("session_hint must be the caller Tenant handle, got %q", gotBody.SessionHint)
	}
	// image is empty on a bare create (PIN-PENDING #205): the gateway must NOT
	// invent it.
	if gotBody.Image != "" {
		t.Errorf("bare create must send empty image (PIN-PENDING #205), got %q", gotBody.Image)
	}
	// The egress_policy MUST be projected from the deployment provisioning so
	// control can materialize (control needs default_deny). It comes from
	// f.provisioning, never a caller body (F5 ruling A).
	if gotBody.EgressPolicy == nil {
		t.Fatal("the F5 create must project egress_policy from provisioning (control needs it to materialize); got none")
	}
	if !gotBody.EgressPolicy.DefaultDeny {
		t.Errorf("egress_policy.default_deny must be projected true from provisioning, got false")
	}
	// The mounts are projected as the plural mount_intents list; the legacy
	// singular field must stay ABSENT (control would reject a body setting both).
	if gotBody.MountIntent != nil {
		t.Errorf("the gateway must not emit the legacy singular mount_intent, got %+v", gotBody.MountIntent)
	}
	if len(gotBody.MountIntents) == 0 {
		t.Error("mount_intents must be projected from the deployment provisioning")
	}
	for _, m := range gotBody.MountIntents {
		hasFS := m.FilesystemID != ""
		hasMem := m.MemoryStoreID != ""
		if hasFS == hasMem {
			t.Errorf("every mount_intents entry must name exactly one scope (filesystem_id XOR memory_store_id), got fs=%q mem=%q", m.FilesystemID, m.MemoryStoreID)
		}
	}

	// The reply is mapped into a SessionResponse. The host-derived key is surfaced
	// as the stable correlation handle (identifier-minimization, invariant #5).
	if resp.Correlation == "" {
		t.Error("the 201 reply key must map into SessionResponse.Correlation")
	}
}

// TestForwardDoesNotForwardServiceTokenAsCallerBearer proves the caller credential
// never rides F5 and the gateway presents only its OWN service principal. The
// control side sees the gateway service token (if any auth header is used at all),
// never a caller sk-ocu- key — there is no field on SessionRequest to carry one.
func TestForwardDoesNotLeakCallerCredential(t *testing.T) {
	pki := newMTLSTestPKI(t)

	var gotAuthHeader string
	var rawBody []byte
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuthHeader = r.Header.Get("Authorization")
		rawBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"key":"k","state":2}`))
	}))
	srv.TLS = pki.serverTLSConfig()
	srv.StartTLS()
	defer srv.Close()

	f, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "ocu-mcp-gateway"},
		DialConfig{Endpoint: srv.URL, TLS: pki.clientTLSConfig()},
		staticCred{token: "gateway-service-token", principal: "ocu-mcp-gateway"},
		validProvisioning(),
	)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}

	if _, err := f.Forward(context.Background(), SessionRequest{
		Principal: auth.Caller{KeyID: "k1", Tenant: "tenant-a"},
	}); err != nil {
		t.Fatalf("forward: %v", err)
	}

	// A caller sk-ocu- key must NEVER appear on F5 — not in a header, not in the body.
	if strings.Contains(gotAuthHeader, "sk-ocu-") || strings.Contains(string(rawBody), "sk-ocu-") {
		t.Errorf("caller sk-ocu- credential must never ride F5; header=%q body=%s", gotAuthHeader, rawBody)
	}
}

// TestForwardFailsClosedOnControlError proves a non-2xx control reply is a
// fail-closed refusal (ErrForwardFailed), never a fabricated success — the forward
// boundary stays fail-closed (invariant #9).
func TestForwardFailsClosedOnControlError(t *testing.T) {
	pki := newMTLSTestPKI(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = w.Write([]byte("request refused"))
	}))
	srv.TLS = pki.serverTLSConfig()
	srv.StartTLS()
	defer srv.Close()

	f, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "ocu-mcp-gateway"},
		DialConfig{Endpoint: srv.URL, TLS: pki.clientTLSConfig()},
		staticCred{token: "t", principal: "ocu-mcp-gateway"},
		validProvisioning(),
	)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if _, ferr := f.Forward(context.Background(), SessionRequest{Principal: auth.Caller{Tenant: "tenant-a"}}); !errors.Is(ferr, ErrForwardFailed) {
		t.Fatalf("a non-2xx control reply must fail closed with ErrForwardFailed, got %v", ferr)
	}
}

// TestDestroyLiveRoundTrip proves the cooperative service teardown is LIVE over
// mTLS: a POST /v1alpha/sessions/destroy carrying the session hint, the client cert
// presented, a 200 accepted. It is the destroy counterpart of the create round-trip.
func TestDestroyLiveRoundTrip(t *testing.T) {
	pki := newMTLSTestPKI(t)

	var gotPath, gotMethod string
	var gotBody destroyBodyWire
	var sawClientCert bool
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotMethod = r.Method
		sawClientCert = r.TLS != nil && len(r.TLS.PeerCertificates) > 0
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		_ = dec.Decode(&gotBody)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("destroyed"))
	}))
	srv.TLS = pki.serverTLSConfig()
	srv.StartTLS()
	defer srv.Close()

	f, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "ocu-mcp-gateway"},
		DialConfig{Endpoint: srv.URL, TLS: pki.clientTLSConfig()},
		staticCred{token: "service-tok", principal: "ocu-mcp-gateway"},
		validProvisioning(),
	)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}

	if derr := f.Destroy(context.Background(), "tenant-a"); derr != nil {
		t.Fatalf("live destroy must succeed over mTLS, got %v", derr)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1alpha/sessions/destroy" {
		t.Errorf("destroy must POST /v1alpha/sessions/destroy, got %s %s", gotMethod, gotPath)
	}
	if !sawClientCert {
		t.Error("destroy must present the gateway client certificate (mTLS)")
	}
	if gotBody.SessionHint != "tenant-a" {
		t.Errorf("destroy must carry the session hint, got %q", gotBody.SessionHint)
	}
}

// TestDestroyFailsClosedOnControlError proves a non-2xx destroy reply is a
// fail-closed refusal, never a fabricated teardown (a foreign/absent hint yields a
// not-found the caller must see as a refusal).
func TestDestroyFailsClosedOnControlError(t *testing.T) {
	pki := newMTLSTestPKI(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("session not addressable"))
	}))
	srv.TLS = pki.serverTLSConfig()
	srv.StartTLS()
	defer srv.Close()

	f, err := NewControlForwarderWithDial(
		ServiceIdentity{Name: "ocu-mcp-gateway"},
		DialConfig{Endpoint: srv.URL, TLS: pki.clientTLSConfig()},
		staticCred{token: "t", principal: "ocu-mcp-gateway"},
		validProvisioning(),
	)
	if err != nil {
		t.Fatalf("construct: %v", err)
	}
	if derr := f.Destroy(context.Background(), "foreign-hint"); !errors.Is(derr, ErrForwardFailed) {
		t.Fatalf("a non-2xx destroy reply must fail closed with ErrForwardFailed, got %v", derr)
	}
}
