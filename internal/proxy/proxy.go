// Package proxy implements the pgppi sidecar: it accepts connections from the
// local Linkerd inbound proxy, reads the PROXY protocol v2 header carrying
// the caller's verified mTLS identity, and opens a PostgreSQL connection that
// authenticates *as that identity* using a freshly minted client certificate.
//
// PostgreSQL then applies `cert map=...` from pg_hba.conf plus pg_ident.conf
// to decide which database roles that identity may log in as. The sidecar
// never decides authorization itself; it only proves identity.
package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/daniel-garcia/pg-ppi/internal/certs"
	"github.com/daniel-garcia/pg-ppi/internal/pgwire"
	"github.com/daniel-garcia/pg-ppi/internal/proxyproto"
)

// UserMode selects the PostgreSQL user name sent to the backend.
type UserMode string

const (
	// UserModeClient forwards the user requested by the client. pg_ident
	// decides whether the caller's identity may use it.
	UserModeClient UserMode = "client"
	// UserModeIdentity replaces the requested user with the caller's
	// Kubernetes ServiceAccount name (the first label of the Linkerd
	// identity), so applications need not know their database role.
	UserModeIdentity UserMode = "identity"
)

// ParseUserMode validates a UserMode string.
func ParseUserMode(s string) (UserMode, error) {
	switch m := UserMode(s); m {
	case UserModeClient, UserModeIdentity:
		return m, nil
	}
	return "", fmt.Errorf("invalid user mode %q (want %q or %q)", s, UserModeClient, UserModeIdentity)
}

// linkerdIdentity matches <sa>.<ns>.serviceaccount.identity.<cp-ns>.<trust-domain>.
var linkerdIdentity = regexp.MustCompile(
	`^[a-z0-9]([-a-z0-9]*[a-z0-9])?\.[a-z0-9]([-a-z0-9]*[a-z0-9])?\.serviceaccount\.identity\.[a-z0-9]([-a-z0-9.]*[a-z0-9])?$`)

// ValidIdentity reports whether id looks like a Linkerd workload identity.
// This guarantees the sidecar can only ever mint certificates for names
// that cannot collide with CloudNativePG's own client certificate CNs
// (e.g. streaming_replica).
func ValidIdentity(id string) bool {
	return len(id) <= 253 && linkerdIdentity.MatchString(id)
}

// Config configures a Server.
type Config struct {
	// BackendAddr is the PostgreSQL TCP address, normally 127.0.0.1:5432.
	BackendAddr string
	// BackendTLS is the base TLS configuration used to verify PostgreSQL's
	// server certificate (RootCAs, ServerName). The client certificate is
	// supplied per connection.
	BackendTLS *tls.Config
	// Issuer mints client certificates for identities.
	Issuer *certs.Issuer
	// UserMode selects which PostgreSQL user is requested.
	UserMode UserMode
	// Replication selects which replication connections are forwarded.
	// The zero value rejects all of them.
	Replication ReplicationPolicy
	// HandshakeTimeout bounds the time from accept until the backend has
	// received the StartupMessage.
	HandshakeTimeout time.Duration
	// Logger receives structured logs.
	Logger *slog.Logger
}

// Server is the pgppi sidecar.
type Server struct {
	cfg Config
	wg  sync.WaitGroup
}

// New returns a Server.
func New(cfg Config) *Server {
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = 10 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.UserMode == "" {
		cfg.UserMode = UserModeClient
	}
	if cfg.Replication == "" {
		cfg.Replication = ReplicationPolicyNone
	}
	return &Server{cfg: cfg}
}

// Serve accepts connections until ctx is canceled or ln fails. It waits for
// in-flight connections to finish before returning.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	stop := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stop()
	defer s.wg.Wait()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		s.wg.Go(func() { s.handle(ctx, conn) })
	}
}

// rejection is an error that is reported to the client as an ErrorResponse.
type rejection struct {
	sqlstate string
	msg      string
}

func (r *rejection) Error() string { return r.msg }

func reject(sqlstate, format string, args ...any) error {
	return &rejection{sqlstate: sqlstate, msg: fmt.Sprintf(format, args...)}
}

func (s *Server) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	log := s.cfg.Logger.With("peer", client.RemoteAddr().String())

	backend, err := s.handshake(ctx, client, &log)
	if err != nil {
		if errors.Is(err, errCancelForwarded) {
			return
		}
		var rej *rejection
		if errors.As(err, &rej) {
			log.Warn("rejecting connection", "reason", rej.msg)
			_, _ = client.Write(pgwire.ErrorResponse(rej.sqlstate, "pgppi: "+rej.msg))
		} else {
			log.Warn("connection failed", "error", err)
		}
		return
	}
	defer backend.Close()

	splice(client, backend)
	log.Debug("connection closed")
}

var errCancelForwarded = errors.New("cancel request forwarded")

// handshake consumes the PROXY header and startup phase from the client and
// returns an authenticated-in-progress backend connection. From that point,
// all remaining bytes (including the backend's authentication response) are
// spliced verbatim.
func (s *Server) handshake(ctx context.Context, client net.Conn, log **slog.Logger) (net.Conn, error) {
	deadline := time.Now().Add(s.cfg.HandshakeTimeout)
	_ = client.SetDeadline(deadline)
	defer func() { _ = client.SetDeadline(time.Time{}) }()

	hdr, err := proxyproto.Read(client)
	if err != nil {
		return nil, reject(pgwire.SQLStateProtocolViolation,
			"connection did not arrive through the Linkerd proxy with PROXY protocol v2 enabled: %v", err)
	}
	if hdr.Command != proxyproto.CommandProxy {
		return nil, reject(pgwire.SQLStateProtocolViolation, "PROXY protocol LOCAL connections are not accepted")
	}

	// Identity problems are reported only after SSL negotiation, once the
	// client expects a normal message; an ErrorResponse in place of the
	// one-byte SSLRequest reply is hidden by libpq.
	identity, ok := hdr.ClientID()
	var identityErr error
	switch {
	case !ok:
		identityErr = reject(pgwire.SQLStateInvalidAuthorization,
			"no verified client identity: the client %s is not meshed or did not use mTLS", hdr.Source)
	case !ValidIdentity(identity):
		identityErr = reject(pgwire.SQLStateInvalidAuthorization, "malformed client identity %q", identity)
	default:
		*log = (*log).With("client", hdr.Source.String(), "identity", identity)
	}

	startup, err := readStartup(client)
	if identityErr != nil {
		return nil, identityErr
	}
	if err != nil {
		if errors.Is(err, errCancelRequest) {
			return nil, s.forwardCancel(ctx, startup)
		}
		return nil, err
	}

	msg, err := pgwire.ParseStartupMessage(startup)
	if err != nil {
		return nil, reject(pgwire.SQLStateProtocolViolation, "%v", err)
	}
	repl, err := ClassifyReplication(msg.Get("replication"))
	if err != nil {
		return nil, reject(pgwire.SQLStateProtocolViolation, "%v", err)
	}
	if !s.cfg.Replication.Allows(repl) {
		return nil, reject(pgwire.SQLStateInvalidAuthorization,
			"%s replication connections are not allowed (replication policy %q)", repl, s.cfg.Replication)
	}
	requested, _ := msg.Get("user")
	user := requested
	if s.cfg.UserMode == UserModeIdentity {
		user, _, _ = strings.Cut(identity, ".")
		msg.Set("user", user)
	}
	if user == "" {
		return nil, reject(pgwire.SQLStateInvalidAuthorization, "no user name specified")
	}
	if _, ok := msg.Get("database"); !ok && requested != "" && requested != user {
		// PostgreSQL defaults the database to the user name; keep the
		// client's original default when we rewrote the user.
		msg.Set("database", requested)
	}
	*log = (*log).With("user", user)
	if repl != ReplicationNone {
		*log = (*log).With("replication", repl.String())
	}

	backend, err := s.dialBackend(ctx, deadline, identity)
	if err != nil {
		return nil, reject(pgwire.SQLStateConnectionFailure, "connecting to PostgreSQL: %v", err)
	}
	if _, err := backend.Write(msg.Encode()); err != nil {
		backend.Close()
		return nil, reject(pgwire.SQLStateConnectionFailure, "sending startup to PostgreSQL: %v", err)
	}
	(*log).Info("proxying connection")
	return backend, nil
}

var errCancelRequest = errors.New("cancel request")

// readStartup reads startup-phase packets, declining SSL/GSS encryption
// (the hop from the Linkerd proxy is loopback-local and mTLS already
// protected the network hop), until a StartupMessage or CancelRequest.
func readStartup(client net.Conn) (*pgwire.Packet, error) {
	for range 3 {
		p, err := pgwire.ReadPacket(client)
		if err != nil {
			if errors.Is(err, pgwire.ErrDirectTLS) {
				return nil, reject(pgwire.SQLStateProtocolViolation,
					"direct TLS is not supported; use sslnegotiation=postgres (encryption is provided by Linkerd mTLS)")
			}
			return nil, fmt.Errorf("reading startup packet: %w", err)
		}
		switch p.Code {
		case pgwire.SSLRequestCode, pgwire.GSSENCRequestCode:
			if _, err := client.Write([]byte{'N'}); err != nil {
				return nil, err
			}
		case pgwire.CancelRequestCode:
			return p, errCancelRequest
		default:
			return p, nil
		}
	}
	return nil, reject(pgwire.SQLStateProtocolViolation, "too many encryption negotiation requests")
}

// forwardCancel relays a CancelRequest. Cancel requests carry a secret key
// and are not subject to pg_hba.conf, so they need no client certificate.
func (s *Server) forwardCancel(ctx context.Context, p *pgwire.Packet) error {
	d := net.Dialer{Timeout: s.cfg.HandshakeTimeout}
	c, err := d.DialContext(ctx, "tcp", s.cfg.BackendAddr)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.Write(p.Encode())
	if err != nil {
		return err
	}
	// PostgreSQL closes the connection without replying.
	_, _ = io.Copy(io.Discard, c)
	return errCancelForwarded
}

func (s *Server) dialBackend(ctx context.Context, deadline time.Time, identity string) (net.Conn, error) {
	cert, err := s.cfg.Issuer.ClientCertificate(identity)
	if err != nil {
		return nil, err
	}

	d := net.Dialer{Deadline: deadline}
	raw, err := d.DialContext(ctx, "tcp", s.cfg.BackendAddr)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(deadline)

	if _, err := raw.Write(pgwire.SSLRequest()); err != nil {
		raw.Close()
		return nil, err
	}
	var resp [1]byte
	if _, err := io.ReadFull(raw, resp[:]); err != nil {
		raw.Close()
		return nil, err
	}
	if resp[0] != 'S' {
		raw.Close()
		return nil, fmt.Errorf("PostgreSQL refused TLS (response %q); ssl must be enabled for cert authentication", resp[0])
	}

	cfg := s.cfg.BackendTLS.Clone()
	cfg.Certificates = []tls.Certificate{*cert}
	conn := tls.Client(raw, cfg)
	if err := conn.HandshakeContext(ctx); err != nil {
		raw.Close()
		return nil, fmt.Errorf("TLS handshake: %w", err)
	}
	_ = raw.SetDeadline(time.Time{})
	return conn, nil
}

// BackendTLSConfig builds the TLS configuration for connecting to
// PostgreSQL. If roots is nil the server certificate is not verified; this
// is only acceptable because the backend is on the pod's loopback.
func BackendTLSConfig(roots *x509.CertPool, serverName string) *tls.Config {
	cfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		RootCAs:    roots,
	}
	if roots == nil {
		cfg.InsecureSkipVerify = true
	}
	return cfg
}

type closeWriter interface{ CloseWrite() error }

// splice copies bytes in both directions until either side closes.
func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		_, _ = io.Copy(dst, src)
		if cw, ok := dst.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
	// Once one direction finishes, give the other a moment to drain (e.g.
	// the backend's reply to Terminate), then tear both down.
	t := time.AfterFunc(5*time.Second, func() { a.Close(); b.Close() })
	<-done
	t.Stop()
}
