// Package plugin implements a CloudNativePG CNPG-I plugin that injects the
// pgppi sidecar into PostgreSQL instance pods and opts those pods into the
// Linkerd mesh with PROXY protocol v2 enabled on the sidecar's port.
package plugin

import (
	"fmt"
	"os"
	"strconv"

	apiv1 "github.com/cloudnative-pg/api/pkg/api/v1"
	"github.com/cloudnative-pg/cnpg-i-machinery/pkg/pluginhelper/common"
	"github.com/cloudnative-pg/cnpg-i-machinery/pkg/pluginhelper/validation"
	"github.com/cloudnative-pg/cnpg-i/pkg/identity"
	"github.com/cloudnative-pg/cnpg-i/pkg/operator"

	"github.com/daniel-garcia/pg-ppi/internal/proxy"
)

// Name is the plugin name referenced from Cluster.spec.plugins[].name.
const Name = "pgppi.daniel-garcia.github.io"

// SidecarImageEnv is the environment variable, set on the plugin Deployment,
// that provides the default sidecar image (normally the plugin's own image).
const SidecarImageEnv = "PGPPI_SIDECAR_IMAGE"

// Metadata is reported to the operator.
var Metadata = identity.GetPluginMetadataResponse{
	Name:          Name,
	Version:       "0.1.0",
	DisplayName:   "pgppi: Linkerd identity to PostgreSQL role",
	ProjectUrl:    "https://github.com/daniel-garcia/pg-ppi",
	RepositoryUrl: "https://github.com/daniel-garcia/pg-ppi",
	License:       "Apache-2.0",
	LicenseUrl:    "https://github.com/daniel-garcia/pg-ppi/blob/main/LICENSE",
	Maturity:      "alpha",
}

// Parameter names accepted in Cluster.spec.plugins[].parameters.
const (
	paramImage    = "image"
	paramPort     = "port"
	paramUserMode = "userMode"
	paramRepl     = "allowReplication"
	paramLinkerd  = "linkerd"
	paramLogLevel = "logLevel"
)

const defaultPort = 15432

// Config is the validated plugin configuration for a Cluster.
type Config struct {
	Image    string
	Port     int32
	UserMode proxy.UserMode
	// Replication selects which replication connections the sidecar
	// forwards (none, logical, all).
	Replication proxy.ReplicationPolicy
	// Linkerd, when true, annotates instance pods for Linkerd injection,
	// marks the sidecar port opaque and enables PROXY protocol v2 on it.
	Linkerd  bool
	LogLevel string
}

// reservedPorts cannot be used for the sidecar: PostgreSQL, the CNPG
// instance manager, and Linkerd's proxy ports.
func reservedPort(p int) bool {
	switch {
	case p == 5432, p == 8000, p == 9187:
		return true
	case p >= 4140 && p <= 4191:
		return true
	}
	return false
}

// FromCluster parses and validates the plugin parameters.
func FromCluster(helper *common.Plugin) (*Config, []*operator.ValidationError) {
	var errs []*operator.ValidationError
	p := helper.Parameters
	fail := func(param, format string, args ...any) {
		errs = append(errs, validation.BuildErrorForParameter(helper, param, fmt.Sprintf(format, args...)))
	}

	cfg := &Config{
		Image:       p[paramImage],
		Port:        defaultPort,
		UserMode:    proxy.UserModeClient,
		Replication: proxy.ReplicationPolicyNone,
		Linkerd:     true,
		LogLevel:    "info",
	}
	if cfg.Image == "" {
		cfg.Image = os.Getenv(SidecarImageEnv)
	}
	if cfg.Image == "" {
		fail(paramImage, "no sidecar image configured and %s is not set on the plugin", SidecarImageEnv)
	}
	if v, ok := p[paramPort]; ok {
		n, err := strconv.Atoi(v)
		switch {
		case err != nil || n < 1024 || n > 65535:
			fail(paramPort, "must be an integer in [1024, 65535], got %q", v)
		case reservedPort(n):
			fail(paramPort, "port %d is reserved by PostgreSQL, CloudNativePG or Linkerd", n)
		default:
			cfg.Port = int32(n)
		}
	}
	if v, ok := p[paramUserMode]; ok {
		m, err := proxy.ParseUserMode(v)
		if err != nil {
			fail(paramUserMode, "%v", err)
		}
		cfg.UserMode = m
	}
	if v, ok := p[paramRepl]; ok {
		r, err := proxy.ParseReplicationPolicy(v)
		if err != nil {
			fail(paramRepl, "%v", err)
		}
		cfg.Replication = r
	}
	if v, ok := p[paramLinkerd]; ok {
		b, err := strconv.ParseBool(v)
		if err != nil {
			fail(paramLinkerd, "must be a boolean, got %q", v)
		}
		cfg.Linkerd = b
	}
	if v, ok := p[paramLogLevel]; ok {
		switch v {
		case "debug", "info", "warn", "error":
			cfg.LogLevel = v
		default:
			fail(paramLogLevel, "must be one of debug, info, warn, error; got %q", v)
		}
	}
	return cfg, errs
}

// clientCASecret returns the Secret holding the CA PostgreSQL uses to verify
// client certificates (ssl_ca_file). By default CloudNativePG uses a single
// self-signed "<cluster>-ca" for both server and client certificates.
func clientCASecret(c *apiv1.Cluster) string {
	if s := c.Status.Certificates.ClientCASecret; s != "" {
		return s
	}
	if c.Spec.Certificates != nil && c.Spec.Certificates.ClientCASecret != "" {
		return c.Spec.Certificates.ClientCASecret
	}
	return c.Name + "-ca"
}

// serverCASecret returns the Secret holding the CA that signed PostgreSQL's
// server certificate.
func serverCASecret(c *apiv1.Cluster) string {
	if s := c.Status.Certificates.ServerCASecret; s != "" {
		return s
	}
	if c.Spec.Certificates != nil && c.Spec.Certificates.ServerCASecret != "" {
		return c.Spec.Certificates.ServerCASecret
	}
	return c.Name + "-ca"
}
