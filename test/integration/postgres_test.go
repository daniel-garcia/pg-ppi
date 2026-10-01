//go:build integration

// Package integration runs pgppi against a real PostgreSQL (in Docker)
// configured exactly like the Kubernetes deployment: TLS on, `cert` auth
// with a pg_ident map. The test plays the part of the Linkerd inbound proxy
// by writing the PROXY protocol v2 header itself.
package integration

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/daniel-garcia/pg-ppi/internal/certs"
	"github.com/daniel-garcia/pg-ppi/internal/proxy"
	"github.com/daniel-garcia/pg-ppi/internal/proxyproto"
)

const (
	billingID   = "billing.billing.serviceaccount.identity.linkerd.cluster.local"
	reportingID = "reporting.billing.serviceaccount.identity.linkerd.cluster.local"
	ordersID    = "orders.shop.serviceaccount.identity.linkerd.cluster.local"
	intruderID  = "intruder.billing.serviceaccount.identity.linkerd.cluster.local"
	cdcID       = "cdc.billing.serviceaccount.identity.linkerd.cluster.local"
)

const pgHBA = `
local   all  all                 trust
hostssl all  all  all            cert map=linkerd
hostssl replication all all      cert map=linkerd
host    all  all  all            reject
`

// Explicit entries for the billing namespace; a regex entry lets any
// ServiceAccount in the "shop" namespace log in as the role of the same name.
const pgIdent = `
linkerd  billing.billing.serviceaccount.identity.linkerd.cluster.local    billing_app
linkerd  reporting.billing.serviceaccount.identity.linkerd.cluster.local  reporting_app
linkerd  cdc.billing.serviceaccount.identity.linkerd.cluster.local        cdc
linkerd  /^([a-z0-9-]+)\.shop\.serviceaccount\.identity\.linkerd\.cluster\.local$  \1
`

const initSQL = `
CREATE ROLE billing_app   LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE reporting_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE orders        LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE;
-- A CDC connector (e.g. Debezium) needs REPLICATION plus read access.
CREATE ROLE cdc           LOGIN REPLICATION NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE DATABASE app;
\c app
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE TABLE invoices (id serial PRIMARY KEY, amount int NOT NULL);
GRANT SELECT, INSERT ON invoices TO billing_app;
GRANT USAGE ON SEQUENCE invoices_id_seq TO billing_app;
GRANT SELECT ON invoices TO reporting_app;
GRANT SELECT ON invoices TO cdc;
CREATE PUBLICATION invoices_pub FOR TABLE invoices;
`

func TestMain(m *testing.M) {
	if _, err := exec.LookPath("docker"); err != nil {
		fmt.Fprintln(os.Stderr, "docker not found; skipping integration tests")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

type env struct {
	proxyAddr string
}

type opts struct {
	mode        proxy.UserMode
	replication proxy.ReplicationPolicy
	// probeID must be an identity that can log in (as probeUser) under
	// mode; it is used to wait for readiness.
	probeID, probeUser string
}

// setup starts PostgreSQL and pgppi.
func setup(t *testing.T, o opts) *env {
	t.Helper()
	dir := t.TempDir()
	if err := certs.WriteTestCA(dir, "localhost", "127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{"pg_hba.conf": pgHBA, "pg_ident.conf": pgIdent, "init.sql": initSQL} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	image := os.Getenv("POSTGRES_IMAGE")
	if image == "" {
		image = "postgres:17"
	}
	// Copy the mounted files so they are owned by postgres with the modes
	// PostgreSQL insists on, regardless of how the host shares volumes.
	script := `set -e
mkdir -p /etc/pgppi /docker-entrypoint-initdb.d
cp /src/ca.crt /src/server.crt /src/server.key /src/pg_hba.conf /src/pg_ident.conf /etc/pgppi/
cp /src/init.sql /docker-entrypoint-initdb.d/
chown -R postgres:postgres /etc/pgppi && chmod 600 /etc/pgppi/server.key
exec docker-entrypoint.sh postgres -c ssl=on \
  -c ssl_cert_file=/etc/pgppi/server.crt -c ssl_key_file=/etc/pgppi/server.key \
  -c ssl_ca_file=/etc/pgppi/ca.crt -c wal_level=logical \
  -c hba_file=/etc/pgppi/pg_hba.conf -c ident_file=/etc/pgppi/pg_ident.conf`
	out, err := exec.Command("docker", "run", "-d", "--rm",
		"-e", "POSTGRES_PASSWORD=unused",
		"-v", dir+":/src:ro",
		"-p", "127.0.0.1::5432",
		"--entrypoint", "bash",
		image, "-c", script).CombinedOutput()
	if err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	id := strings.TrimSpace(string(out))
	t.Cleanup(func() {
		if t.Failed() {
			logs, _ := exec.Command("docker", "logs", id).CombinedOutput()
			t.Logf("postgres logs:\n%s", logs)
		}
		_ = exec.Command("docker", "rm", "-f", id).Run()
	})
	out, err = exec.Command("docker", "port", id, "5432/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	backend := strings.TrimSpace(strings.Split(string(out), "\n")[0])

	iss, err := certs.NewIssuer(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	srv := proxy.New(proxy.Config{
		BackendAddr: backend,
		BackendTLS:  proxy.BackendTLSConfig(roots, "localhost"),
		Issuer:      iss,
		UserMode:    o.mode,
		Replication: o.replication,
		Logger:      slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug})),
	})
	go func() { _ = srv.Serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	e := &env{proxyAddr: ln.Addr().String()}
	e.waitReady(t, o.probeID, o.probeUser)
	return e
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimRight(string(p), "\n"))
	return len(p), nil
}

// connect dials through pgppi, writing a PROXY header for identity first
// (as the Linkerd inbound proxy would). An empty identity simulates a
// connection from an unmeshed client.
func (e *env) connect(ctx context.Context, t *testing.T, identity, user string) (*pgx.Conn, error) {
	t.Helper()
	return pgx.ConnectConfig(ctx, e.config(t, identity, user))
}

// connectReplication opens a walsender connection (replication=database for
// logical, replication=true for physical) the way Debezium/pglogrepl do.
func (e *env) connectReplication(ctx context.Context, t *testing.T, identity, user, replication string) (*pgconn.PgConn, error) {
	t.Helper()
	cfg := e.config(t, identity, user)
	cfg.RuntimeParams["replication"] = replication
	return pgconn.ConnectConfig(ctx, &cfg.Config)
}

func (e *env) config(t *testing.T, identity, user string) *pgx.ConnConfig {
	t.Helper()
	cfg, err := pgx.ParseConfig(fmt.Sprintf("postgres://%s@%s/app?sslmode=prefer&connect_timeout=5", user, e.proxyAddr))
	if err != nil {
		t.Fatal(err)
	}
	cfg.DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		c, err := (&net.Dialer{}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		var tlvs []proxyproto.TLV
		if identity != "" {
			tlvs = append(tlvs, proxyproto.TLV{Type: proxyproto.TLVTypeLinkerdClientID, Value: []byte(identity)})
		}
		hdr := proxyproto.Encode(netip.MustParseAddrPort("10.244.0.7:41000"), netip.MustParseAddrPort("10.244.0.9:15432"), tlvs...)
		if _, err := c.Write(hdr); err != nil {
			c.Close()
			return nil, err
		}
		return c, nil
	}
	return cfg
}

func (e *env) waitReady(t *testing.T, identity, user string) {
	t.Helper()
	deadline := time.Now().Add(90 * time.Second)
	for {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := e.connect(ctx, t, identity, user)
		cancel()
		if err == nil {
			_ = c.Close(context.Background())
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("PostgreSQL never became ready: %v", err)
		}
		time.Sleep(time.Second)
	}
}

func sqlState(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		return pgErr.Code
	}
	return ""
}

func TestClientUserMode(t *testing.T) {
	e := setup(t, opts{mode: proxy.UserModeClient, probeID: billingID, probeUser: "billing_app"})
	ctx := context.Background()

	t.Run("identity may use its mapped role", func(t *testing.T) {
		c, err := e.connect(ctx, t, billingID, "billing_app")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx)

		var user, dn string
		err = c.QueryRow(ctx, `SELECT current_user, client_dn FROM pg_stat_ssl WHERE pid = pg_backend_pid()`).Scan(&user, &dn)
		if err != nil {
			t.Fatal(err)
		}
		if user != "billing_app" {
			t.Errorf("current_user = %q", user)
		}
		// pg_stat_ssl truncates client_dn to NAMEDATALEN-1 bytes; pg_ident
		// matching (above) uses the full CN.
		if full := "/CN=" + billingID; len(dn) < 32 || !strings.HasPrefix(full, dn) {
			t.Errorf("client_dn = %q, want a prefix of %q", dn, full)
		}

		if _, err := c.Exec(ctx, `INSERT INTO invoices (amount) VALUES (42)`); err != nil {
			t.Errorf("insert: %v", err)
		}
	})

	t.Run("second identity maps to a different role", func(t *testing.T) {
		c, err := e.connect(ctx, t, reportingID, "reporting_app")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx)
		if _, err := c.Exec(ctx, `INSERT INTO invoices (amount) VALUES (1)`); sqlState(err) != "42501" {
			t.Errorf("reporting_app insert: err = %v, want insufficient_privilege", err)
		}
	})

	for name, tc := range map[string]struct{ identity, user string }{
		"identity claims another identity's role": {billingID, "reporting_app"},
		"identity claims superuser":               {billingID, "postgres"},
		"unmapped identity":                       {intruderID, "billing_app"},
		"unmeshed client (no identity TLV)":       {"", "billing_app"},
	} {
		t.Run(name+" is rejected", func(t *testing.T) {
			c, err := e.connect(ctx, t, tc.identity, tc.user)
			if err == nil {
				c.Close(ctx)
				t.Fatal("connection unexpectedly succeeded")
			}
			if s := sqlState(err); s != "28000" {
				t.Errorf("SQLSTATE = %q, want 28000 (%v)", s, err)
			}
		})
	}

	t.Run("no privilege escalation after login", func(t *testing.T) {
		c, err := e.connect(ctx, t, billingID, "billing_app")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx)
		for stmt, want := range map[string]string{
			`SET ROLE reporting_app`:                "42501",
			`SET ROLE postgres`:                     "42501",
			`SET SESSION AUTHORIZATION postgres`:    "42501",
			`CREATE TABLE public.escalate (id int)`: "42501",
		} {
			if _, err := c.Exec(ctx, stmt); sqlState(err) != want {
				t.Errorf("%s: err = %v, want SQLSTATE %s", stmt, err, want)
			}
		}
	})

	t.Run("cancel request is relayed", func(t *testing.T) {
		c, err := e.connect(ctx, t, billingID, "billing_app")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(context.Background())
		qctx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
		defer cancel()
		start := time.Now()
		_, err = c.Exec(qctx, `SELECT pg_sleep(30)`)
		if err == nil {
			t.Fatal("pg_sleep was not canceled")
		}
		if time.Since(start) > 10*time.Second {
			t.Errorf("cancel took %v", time.Since(start))
		}
	})
}

func TestIdentityUserMode(t *testing.T) {
	e := setup(t, opts{mode: proxy.UserModeIdentity, probeID: ordersID})
	ctx := context.Background()

	// The client asks for "postgres", but pgppi logs in as the ServiceAccount
	// name, which the regex map in pg_ident.conf allows.
	c, err := e.connect(ctx, t, ordersID, "postgres")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(ctx)
	var user string
	if err := c.QueryRow(ctx, `SELECT current_user`).Scan(&user); err != nil {
		t.Fatal(err)
	}
	if user != "orders" {
		t.Errorf("current_user = %q, want orders", user)
	}

	// billing's ServiceAccount name ("billing") has no mapping.
	if c, err := e.connect(ctx, t, billingID, "billing_app"); err == nil {
		c.Close(ctx)
		t.Error("expected rejection for unmapped ServiceAccount role")
	}
}

func TestReplication(t *testing.T) {
	ctx := context.Background()

	t.Run("rejected by default", func(t *testing.T) {
		e := setup(t, opts{mode: proxy.UserModeClient, probeID: billingID, probeUser: "billing_app"})
		for _, r := range []string{"database", "true"} {
			if c, err := e.connectReplication(ctx, t, cdcID, "cdc", r); err == nil {
				c.Close(ctx)
				t.Errorf("replication=%s unexpectedly allowed", r)
			} else if !strings.Contains(err.Error(), "not allowed") {
				t.Errorf("replication=%s: err = %v", r, err)
			}
		}
	})

	t.Run("logical", func(t *testing.T) {
		e := setup(t, opts{mode: proxy.UserModeClient, replication: proxy.ReplicationPolicyLogical, probeID: billingID, probeUser: "billing_app"})

		c, err := e.connectReplication(ctx, t, cdcID, "cdc", "database")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx)
		res, err := c.Exec(ctx, "IDENTIFY_SYSTEM").ReadAll()
		if err != nil {
			t.Fatalf("IDENTIFY_SYSTEM: %v", err)
		}
		if len(res) != 1 || len(res[0].Rows) != 1 || string(res[0].Rows[0][3]) != "app" {
			t.Errorf("IDENTIFY_SYSTEM = %+v, want dbname app", res)
		}
		// What a CDC connector does on first start.
		if _, err := c.Exec(ctx, "CREATE_REPLICATION_SLOT pgppi_cdc TEMPORARY LOGICAL pgoutput").ReadAll(); err != nil {
			t.Fatalf("CREATE_REPLICATION_SLOT: %v", err)
		}

		// PostgreSQL still requires the REPLICATION attribute.
		if c, err := e.connectReplication(ctx, t, billingID, "billing_app", "database"); err == nil {
			c.Close(ctx)
			t.Error("NOREPLICATION role opened a walsender")
		} else if s := sqlState(err); s != "42501" {
			t.Errorf("NOREPLICATION role: SQLSTATE %q (%v), want 42501", s, err)
		}
		// ...and pg_ident still applies.
		if c, err := e.connectReplication(ctx, t, billingID, "cdc", "database"); err == nil {
			c.Close(ctx)
			t.Error("billing identity logged in as cdc")
		} else if s := sqlState(err); s != "28000" {
			t.Errorf("billing as cdc: SQLSTATE %q (%v), want 28000", s, err)
		}
		// Physical is not covered by the logical policy.
		if c, err := e.connectReplication(ctx, t, cdcID, "cdc", "true"); err == nil {
			c.Close(ctx)
			t.Error("physical replication allowed under logical policy")
		}
	})

	t.Run("physical", func(t *testing.T) {
		e := setup(t, opts{mode: proxy.UserModeClient, replication: proxy.ReplicationPolicyAll, probeID: billingID, probeUser: "billing_app"})
		c, err := e.connectReplication(ctx, t, cdcID, "cdc", "true")
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close(ctx)
		if _, err := c.Exec(ctx, "IDENTIFY_SYSTEM").ReadAll(); err != nil {
			t.Fatalf("IDENTIFY_SYSTEM: %v", err)
		}
	})
}
