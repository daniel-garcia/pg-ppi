// Command pgppi is both the PostgreSQL identity sidecar ("pgppi proxy") and
// the CloudNativePG CNPG-I plugin that injects it ("pgppi plugin").
package main

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/cloudnative-pg/cnpg-i-machinery/pkg/pluginhelper/http"
	"github.com/cloudnative-pg/cnpg-i/pkg/lifecycle"
	"github.com/cloudnative-pg/cnpg-i/pkg/operator"
	"github.com/cloudnative-pg/machinery/pkg/log"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"

	"github.com/daniel-garcia/pg-ppi/internal/certs"
	"github.com/daniel-garcia/pg-ppi/internal/plugin"
	"github.com/daniel-garcia/pg-ppi/internal/proxy"
)

func main() {
	cobra.EnableTraverseRunHooks = true
	root := &cobra.Command{
		Use:          "pgppi",
		Short:        "Map Linkerd mTLS identities (via PROXY protocol v2) to PostgreSQL roles",
		SilenceUsage: true,
	}
	root.AddCommand(proxyCmd(), pluginCmd())
	if err := root.Execute(); err != nil {
		os.Exit(1)
	}
}

func proxyCmd() *cobra.Command {
	var (
		listenHost, backend, backendServerName, backendCA string
		clientCACert, clientCAKey, userMode, logLevel     string
		replication                                       string
		listenPort                                        int
		certTTL, handshakeTimeout                         time.Duration
	)
	cmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run the sidecar",
		RunE: func(cmd *cobra.Command, _ []string) error {
			var lvl slog.Level
			if err := lvl.UnmarshalText([]byte(logLevel)); err != nil {
				return err
			}
			logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: lvl}))

			mode, err := proxy.ParseUserMode(userMode)
			if err != nil {
				return err
			}
			replPolicy, err := proxy.ParseReplicationPolicy(replication)
			if err != nil {
				return err
			}
			issuer, err := certs.NewIssuer(clientCACert, clientCAKey, certTTL)
			if err != nil {
				return fmt.Errorf("loading client CA: %w", err)
			}
			var roots *x509.CertPool
			if backendCA != "" {
				pem, err := os.ReadFile(backendCA)
				if err != nil {
					return err
				}
				roots = x509.NewCertPool()
				if !roots.AppendCertsFromPEM(pem) {
					return errors.New("--backend-ca: no certificates found")
				}
			} else {
				logger.Warn("--backend-ca not set; PostgreSQL's server certificate will not be verified")
			}

			addr := net.JoinHostPort(listenHost, strconv.Itoa(listenPort))
			ln, err := net.Listen("tcp", addr)
			if err != nil {
				return err
			}
			logger.Info("listening", "addr", ln.Addr().String(), "backend", backend, "userMode", mode, "replication", replPolicy)

			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			return proxy.New(proxy.Config{
				BackendAddr:      backend,
				BackendTLS:       proxy.BackendTLSConfig(roots, backendServerName),
				Issuer:           issuer,
				UserMode:         mode,
				Replication:      replPolicy,
				HandshakeTimeout: handshakeTimeout,
				Logger:           logger,
			}).Serve(ctx, ln)
		},
	}
	f := cmd.Flags()
	f.StringVar(&listenHost, "listen-host", "",
		"address to listen on; bind to the pod IP (where the Linkerd proxy delivers traffic), not loopback, so that other containers cannot forge PROXY headers via 127.0.0.1")
	f.IntVar(&listenPort, "listen-port", 15432, "port to listen on")
	f.StringVar(&backend, "backend", "127.0.0.1:5432", "PostgreSQL address")
	f.StringVar(&backendServerName, "backend-server-name", "", "expected name in PostgreSQL's server certificate")
	f.StringVar(&backendCA, "backend-ca", "", "CA bundle to verify PostgreSQL's server certificate")
	f.StringVar(&clientCACert, "client-ca-cert", "", "CA certificate PostgreSQL trusts for client certificates (ssl_ca_file)")
	f.StringVar(&clientCAKey, "client-ca-key", "", "private key for --client-ca-cert")
	f.StringVar(&userMode, "user-mode", string(proxy.UserModeClient),
		"'client': forward the requested user; 'identity': log in as the caller's ServiceAccount name")
	f.StringVar(&replication, "allow-replication", string(proxy.ReplicationPolicyNone),
		"replication connections to forward: 'none', 'logical' (replication=database, e.g. Debezium) or 'all' (also physical)")
	f.DurationVar(&certTTL, "cert-ttl", time.Hour, "lifetime of minted client certificates")
	f.DurationVar(&handshakeTimeout, "handshake-timeout", 10*time.Second, "timeout for the PROXY/startup handshake")
	f.StringVar(&logLevel, "log-level", "info", "debug, info, warn or error")
	_ = cmd.MarkFlagRequired("client-ca-cert")
	_ = cmd.MarkFlagRequired("client-ca-key")
	return cmd
}

func pluginCmd() *cobra.Command {
	logFlags := &log.Flags{}
	cmd := http.CreateMainCmd(plugin.Identity{}, func(s *grpc.Server) error {
		operator.RegisterOperatorServer(s, plugin.Operator{})
		lifecycle.RegisterOperatorLifecycleServer(s, plugin.Lifecycle{})
		return nil
	})
	cmd.Use = "plugin"
	cmd.Short = "Run the CloudNativePG CNPG-I plugin that injects the sidecar"
	logFlags.AddFlags(cmd.PersistentFlags())
	cmd.PersistentPreRun = func(cmd *cobra.Command, _ []string) {
		logFlags.ConfigureLogging()
		cmd.SetContext(log.IntoContext(contextOrBackground(cmd.Context()), log.GetLogger()))
	}
	return cmd
}

func contextOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}
