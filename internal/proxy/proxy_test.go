package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/daniel-garcia/pg-ppi/internal/certs"
	"github.com/daniel-garcia/pg-ppi/internal/pgwire"
	"github.com/daniel-garcia/pg-ppi/internal/proxyproto"
)

const identity = "billing.billing.serviceaccount.identity.linkerd.cluster.local"

// fakePostgres accepts one TLS-upgraded connection, requires a client
// certificate from the CA, and reports the CN and StartupMessage it saw.
type fakePostgres struct {
	addr string
	seen chan seen
}

type seen struct {
	cn      string
	startup *pgwire.StartupMessage
	err     error
}

func startFakePostgres(t *testing.T, dir string) *fakePostgres {
	t.Helper()
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	srvCert, err := tls.LoadX509KeyPair(filepath.Join(dir, "server.crt"), filepath.Join(dir, "server.key"))
	if err != nil {
		t.Fatal(err)
	}
	tcfg := &tls.Config{
		Certificates: []tls.Certificate{srvCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	fp := &fakePostgres{addr: ln.Addr().String(), seen: make(chan seen, 4)}

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				report := func(s seen) { fp.seen <- s }
				p, err := pgwire.ReadPacket(c)
				if err != nil {
					report(seen{err: err})
					return
				}
				if p.Code == pgwire.CancelRequestCode {
					report(seen{cn: "<cancel>"})
					return
				}
				if p.Code != pgwire.SSLRequestCode {
					report(seen{err: errors.New("expected SSLRequest")})
					return
				}
				_, _ = c.Write([]byte{'S'})
				tc := tls.Server(c, tcfg)
				if err := tc.Handshake(); err != nil {
					report(seen{err: err})
					return
				}
				p, err = pgwire.ReadPacket(tc)
				if err != nil {
					report(seen{err: err})
					return
				}
				m, err := pgwire.ParseStartupMessage(p)
				cn := tc.ConnectionState().PeerCertificates[0].Subject.CommonName
				report(seen{cn: cn, startup: m, err: err})
				// Echo so the test can verify the splice.
				_, _ = tc.Write([]byte("R-ok"))
				_, _ = io.Copy(tc, tc)
			}()
		}
	}()
	return fp
}

func startProxy(t *testing.T, mode UserMode) (addr string, fp *fakePostgres) {
	t.Helper()
	return startProxyWith(t, Config{UserMode: mode})
}

// startProxyWith starts pgppi with cfg; the backend, TLS and issuer fields
// are filled in to point at a fake PostgreSQL.
func startProxyWith(t *testing.T, cfg Config) (addr string, fp *fakePostgres) {
	t.Helper()
	dir := t.TempDir()
	if err := certs.WriteTestCA(dir, "pg-rw"); err != nil {
		t.Fatal(err)
	}
	fp = startFakePostgres(t, dir)

	iss, err := certs.NewIssuer(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)

	cfg.BackendAddr = fp.addr
	cfg.BackendTLS = BackendTLSConfig(roots, "pg-rw")
	cfg.Issuer = iss
	srv := New(cfg)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	return ln.Addr().String(), fp
}

func dial(t *testing.T, addr string, header []byte) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if header != nil {
		if _, err := c.Write(header); err != nil {
			t.Fatal(err)
		}
	}
	return c
}

func linkerdHeader(id string) []byte {
	var tlvs []proxyproto.TLV
	if id != "" {
		tlvs = append(tlvs, proxyproto.TLV{Type: proxyproto.TLVTypeLinkerdClientID, Value: []byte(id)})
	}
	return proxyproto.Encode(
		netip.MustParseAddrPort("10.1.2.3:40000"),
		netip.MustParseAddrPort("10.9.8.7:15432"),
		tlvs...,
	)
}

func startup(user string) []byte {
	m := &pgwire.StartupMessage{ProtocolVersion: 3 << 16, Params: []pgwire.Param{{Name: "user", Value: user}, {Name: "database", Value: "app"}}}
	return m.Encode()
}

// readError reads an ErrorResponse and returns its SQLSTATE.
func readError(t *testing.T, c net.Conn) string {
	t.Helper()
	r := bufio.NewReader(c)
	typ, err := r.ReadByte()
	if err != nil {
		t.Fatalf("reading error response: %v", err)
	}
	if typ != 'E' {
		t.Fatalf("message type = %q, want 'E'", typ)
	}
	body, _ := io.ReadAll(r)
	for f := body[4:]; len(f) > 1; {
		code := f[0]
		end := 1
		for f[end] != 0 {
			end++
		}
		if code == 'C' {
			return string(f[1:end])
		}
		f = f[end+1:]
	}
	t.Fatal("no SQLSTATE in error response")
	return ""
}

func TestProxiesAsIdentity(t *testing.T) {
	addr, fp := startProxy(t, UserModeClient)
	c := dial(t, addr, linkerdHeader(identity))

	// Clients with sslmode=prefer send an SSLRequest first; it is declined.
	_, _ = c.Write(pgwire.SSLRequest())
	var n [1]byte
	if _, err := io.ReadFull(c, n[:]); err != nil || n[0] != 'N' {
		t.Fatalf("SSLRequest response = %q, %v", n, err)
	}

	_, _ = c.Write(startup("billing_app"))
	s := <-fp.seen
	if s.err != nil {
		t.Fatal(s.err)
	}
	if s.cn != identity {
		t.Errorf("backend saw client cert CN %q, want %q", s.cn, identity)
	}
	if u, _ := s.startup.Get("user"); u != "billing_app" {
		t.Errorf("backend saw user %q", u)
	}

	buf := make([]byte, 4)
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "R-ok" {
		t.Fatalf("splice read = %q, %v", buf, err)
	}
	_, _ = c.Write([]byte("ping"))
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("splice echo = %q, %v", buf, err)
	}
}

func TestIdentityUserMode(t *testing.T) {
	addr, fp := startProxy(t, UserModeIdentity)
	c := dial(t, addr, linkerdHeader(identity))
	_, _ = c.Write(startup("postgres"))
	s := <-fp.seen
	if s.err != nil {
		t.Fatal(s.err)
	}
	if u, _ := s.startup.Get("user"); u != "billing" {
		t.Errorf("backend saw user %q, want ServiceAccount name", u)
	}
}

func TestRejections(t *testing.T) {
	addr, _ := startProxy(t, UserModeClient)

	tests := map[string]struct {
		header  []byte
		startup []byte
		state   string
	}{
		"no PROXY header": {
			header: startup("billing_app"),
			state:  pgwire.SQLStateProtocolViolation,
		},
		"no identity (unmeshed client)": {
			header:  linkerdHeader(""),
			startup: startup("billing_app"),
			state:   pgwire.SQLStateInvalidAuthorization,
		},
		"not a linkerd identity": {
			header:  linkerdHeader("streaming_replica"),
			startup: startup("streaming_replica"),
			state:   pgwire.SQLStateInvalidAuthorization,
		},
		"replication": {
			header: linkerdHeader(identity),
			startup: (&pgwire.StartupMessage{ProtocolVersion: 3 << 16, Params: []pgwire.Param{
				{Name: "user", Value: "billing_app"}, {Name: "replication", Value: "database"},
			}}).Encode(),
			state: pgwire.SQLStateInvalidAuthorization,
		},
		"direct TLS": {
			header:  linkerdHeader(identity),
			startup: []byte{0x16, 0x03, 0x01, 0x00, 0x10, 0x01, 0x00, 0x00},
			state:   pgwire.SQLStateProtocolViolation,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			c := dial(t, addr, tc.header)
			if tc.startup != nil {
				_, _ = c.Write(tc.startup)
			}
			if got := readError(t, c); got != tc.state {
				t.Errorf("SQLSTATE = %s, want %s", got, tc.state)
			}
		})
	}
}

func TestCancelForwarded(t *testing.T) {
	addr, fp := startProxy(t, UserModeClient)
	c := dial(t, addr, linkerdHeader(identity))
	_, _ = c.Write((&pgwire.Packet{Code: pgwire.CancelRequestCode, Payload: make([]byte, 8)}).Encode())
	if s := <-fp.seen; s.cn != "<cancel>" {
		t.Fatalf("backend saw %+v, want cancel request", s)
	}
}

func TestValidIdentity(t *testing.T) {
	for id, want := range map[string]bool{
		identity: true,
		"web.emojivoto.serviceaccount.identity.linkerd.cluster.local": true,
		"a.b.serviceaccount.identity.linkerd.example.org":             true,
		"streaming_replica": false,
		"postgres":          false,
		"Billing.billing.serviceaccount.identity.linkerd.cluster.local": false,
		"billing.serviceaccount.identity.linkerd.cluster.local":         false,
		"a.b.serviceaccount.identity.":                                  false,
	} {
		if got := ValidIdentity(id); got != want {
			t.Errorf("ValidIdentity(%q) = %v, want %v", id, got, want)
		}
	}
}

// libpq discards an ErrorResponse sent in reply to SSLRequest, so identity
// rejections must wait until the StartupMessage.
func TestNoIdentityRejectedAfterSSLNegotiation(t *testing.T) {
	addr, _ := startProxy(t, UserModeClient)
	c := dial(t, addr, linkerdHeader(""))
	_, _ = c.Write(pgwire.SSLRequest())
	var n [1]byte
	if _, err := io.ReadFull(c, n[:]); err != nil || n[0] != 'N' {
		t.Fatalf("SSLRequest response = %q, %v; want 'N'", n, err)
	}
	_, _ = c.Write(startup("billing_app"))
	if got := readError(t, c); got != pgwire.SQLStateInvalidAuthorization {
		t.Errorf("SQLSTATE = %s", got)
	}
}

func TestClassifyReplication(t *testing.T) {
	for v, want := range map[string]ReplicationKind{
		"database": ReplicationLogical,
		"true":     ReplicationPhysical, "on": ReplicationPhysical, "yes": ReplicationPhysical,
		"1": ReplicationPhysical, "T": ReplicationPhysical, "Y": ReplicationPhysical,
		"false": ReplicationNone, "off": ReplicationNone, "no": ReplicationNone,
		"0": ReplicationNone, "of": ReplicationNone, "F": ReplicationNone,
	} {
		got, err := ClassifyReplication(v, true)
		if err != nil || got != want {
			t.Errorf("ClassifyReplication(%q) = %v, %v; want %v", v, got, err, want)
		}
	}
	// "database" is case-sensitive in PostgreSQL; "o" is ambiguous.
	for _, v := range []string{"Database", "o", "", "2", "maybe"} {
		if _, err := ClassifyReplication(v, true); err == nil {
			t.Errorf("ClassifyReplication(%q): expected error", v)
		}
	}
	if k, err := ClassifyReplication("", false); err != nil || k != ReplicationNone {
		t.Errorf("absent parameter = %v, %v", k, err)
	}
}

func TestReplicationPolicy(t *testing.T) {
	replStartup := func(v string) []byte {
		return (&pgwire.StartupMessage{ProtocolVersion: 3 << 16, Params: []pgwire.Param{
			{Name: "user", Value: "cdc"}, {Name: "database", Value: "app"}, {Name: "replication", Value: v},
		}}).Encode()
	}
	for _, tc := range []struct {
		policy  ReplicationPolicy
		value   string
		allowed bool
	}{
		{ReplicationPolicyNone, "false", true},
		{ReplicationPolicyNone, "database", false},
		{ReplicationPolicyNone, "true", false},
		{ReplicationPolicyLogical, "database", true},
		{ReplicationPolicyLogical, "true", false},
		{ReplicationPolicyAll, "database", true},
		{ReplicationPolicyAll, "yes", true},
	} {
		t.Run(fmt.Sprintf("%s/%s", tc.policy, tc.value), func(t *testing.T) {
			addr, fp := startProxyWith(t, Config{UserMode: UserModeClient, Replication: tc.policy})
			c := dial(t, addr, linkerdHeader(identity))
			_, _ = c.Write(replStartup(tc.value))
			if !tc.allowed {
				if got := readError(t, c); got != pgwire.SQLStateInvalidAuthorization {
					t.Errorf("SQLSTATE = %s", got)
				}
				return
			}
			s := <-fp.seen
			if s.err != nil {
				t.Fatal(s.err)
			}
			// The parameter is forwarded untouched for PostgreSQL to act on.
			if v, _ := s.startup.Get("replication"); v != tc.value {
				t.Errorf("backend saw replication=%q", v)
			}
		})
	}
}
