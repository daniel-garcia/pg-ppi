//go:build e2e

// Package e2e runs against the kind cluster created by hack/e2e-setup.sh:
// Linkerd (with linkerd/linkerd2#15676 and linkerd/linkerd2-proxy#4625),
// CloudNativePG, and the pgppi CNPG-I plugin. Clients in the "billing"
// namespace run psql via kubectl exec.
package e2e

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

var kubeContext = func() string {
	if c := os.Getenv("KUBE_CONTEXT"); c != "" {
		return c
	}
	return "kind-pgppi"
}()

const (
	pgppiHost = "pg-pgppi.db.svc.cluster.local"
	rwHost    = "pg-rw.db.svc.cluster.local"
	instance  = "pg-1"
)

func kubectl(args ...string) (string, error) {
	out, err := exec.Command("kubectl", append([]string{"--context", kubeContext}, args...)...).CombinedOutput()
	return string(out), err
}

// psql runs a query from the given client Deployment in the billing
// namespace and returns combined output.
func psql(client, host, port, user, query string) (string, error) {
	return psqlDSN(client, fmt.Sprintf("host=%s port=%s dbname=app user=%s sslmode=prefer connect_timeout=10", host, port, user), query)
}

func psqlDSN(client, dsn, query string) (string, error) {
	return kubectl("-n", "billing", "exec", "deploy/"+client, "-c", "client", "--",
		"psql", dsn, "-w", "-X", "-v", "ON_ERROR_STOP=1", "-tA", "-c", query)
}

func TestInstancePodInjection(t *testing.T) {
	out, err := kubectl("-n", "db", "get", "pod", instance, "-o", "json")
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	var pod struct {
		Metadata struct {
			Annotations map[string]string `json:"annotations"`
		} `json:"metadata"`
		Spec struct {
			InitContainers []container `json:"initContainers"`
			Containers     []container `json:"containers"`
		} `json:"spec"`
	}
	if err := json.Unmarshal([]byte(out), &pod); err != nil {
		t.Fatal(err)
	}
	all := append(pod.Spec.InitContainers, pod.Spec.Containers...)
	names := []string{}
	for _, c := range all {
		names = append(names, c.Name)
	}
	for _, want := range []string{"postgres", "pgppi", "linkerd-proxy"} {
		if !slices.Contains(names, want) {
			t.Errorf("instance pod containers %v missing %q", names, want)
		}
	}

	// Set by the plugin...
	if got := pod.Metadata.Annotations["config.linkerd.io/proxy-protocol-v2-inbound-ports"]; got != "15432" {
		t.Errorf("proxy-protocol-v2-inbound-ports annotation = %q", got)
	}
	// ...and rendered by the proxy injector from linkerd/linkerd2#15676.
	i := slices.IndexFunc(all, func(c container) bool { return c.Name == "linkerd-proxy" })
	if i < 0 {
		return
	}
	var env string
	for _, e := range all[i].Env {
		if e.Name == "LINKERD2_PROXY_INBOUND_PORTS_PROXY_PROTOCOL_V2" {
			env = e.Value
		}
	}
	if env != "15432" {
		t.Errorf("linkerd-proxy LINKERD2_PROXY_INBOUND_PORTS_PROXY_PROTOCOL_V2 = %q, want 15432", env)
	}
}

type container struct {
	Name string `json:"name"`
	Env  []struct {
		Name  string `json:"name"`
		Value string `json:"value"`
	} `json:"env"`
}

func TestAllowed(t *testing.T) {
	for _, tc := range []struct{ client, user string }{
		{"billing", "billing_app"},
		{"reporting", "reporting_app"},
	} {
		t.Run(tc.client+" as "+tc.user, func(t *testing.T) {
			out, err := psql(tc.client, pgppiHost, "15432", tc.user, "SELECT current_user")
			if err != nil {
				t.Fatalf("%v: %s", err, out)
			}
			if got := strings.TrimSpace(out); got != tc.user {
				t.Errorf("current_user = %q, want %q", got, tc.user)
			}
		})
	}

	t.Run("billing writes, reporting only reads", func(t *testing.T) {
		if out, err := psql("billing", pgppiHost, "15432", "billing_app", "INSERT INTO invoices (amount) VALUES (42)"); err != nil {
			t.Fatalf("%v: %s", err, out)
		}
		if out, err := psql("reporting", pgppiHost, "15432", "reporting_app", "SELECT count(*) > 0 FROM invoices"); err != nil || strings.TrimSpace(out) != "t" {
			t.Fatalf("reporting read: %v: %s", err, out)
		}
		out, err := psql("reporting", pgppiHost, "15432", "reporting_app", "INSERT INTO invoices (amount) VALUES (1)")
		if err == nil || !strings.Contains(out, "permission denied") {
			t.Errorf("reporting insert: err=%v out=%s", err, out)
		}
	})
}

func TestDenied(t *testing.T) {
	for _, tc := range []struct {
		name, client, host, port, user, want string
	}{
		{"identity claims another identity's role", "billing", pgppiHost, "15432", "reporting_app", "certificate authentication failed"},
		{"identity claims superuser", "billing", pgppiHost, "15432", "postgres", "certificate authentication failed"},
		{"identity claims database owner", "billing", pgppiHost, "15432", "app", "certificate authentication failed"},
		{"unmapped identity", "intruder", pgppiHost, "15432", "billing_app", "certificate authentication failed"},
		{"unmeshed client", "unmeshed", pgppiHost, "15432", "billing_app", "no verified client identity"},
		{"bypassing pgppi requires a password", "billing", rwHost, "5432", "billing_app", "password"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := psql(tc.client, tc.host, tc.port, tc.user, "SELECT current_user")
			if err == nil {
				t.Fatalf("connection unexpectedly succeeded: %s", out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("output %q does not contain %q", out, tc.want)
			}
		})
	}
}

func TestNoEscalationAfterLogin(t *testing.T) {
	for _, stmt := range []string{
		"SET ROLE reporting_app",
		"SET ROLE postgres",
		"SET SESSION AUTHORIZATION postgres",
		"CREATE TABLE public.escalate (id int)",
	} {
		t.Run(stmt, func(t *testing.T) {
			out, err := psql("billing", pgppiHost, "15432", "billing_app", stmt)
			if err == nil || !strings.Contains(out, "permission denied") {
				t.Errorf("err=%v out=%s", err, out)
			}
		})
	}
}

func TestSidecarLogsIdentity(t *testing.T) {
	if out, err := psql("billing", pgppiHost, "15432", "billing_app", "SELECT 1"); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	out, err := kubectl("-n", "db", "logs", instance, "-c", "pgppi", "--tail=200")
	if err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if !strings.Contains(out, `"identity":"billing.billing.serviceaccount.identity.linkerd.cluster.local"`) {
		t.Errorf("sidecar logs do not show the billing identity:\n%s", out)
	}
}

// TestLogicalReplication does what a CDC connector such as Debezium does on
// startup: open a walsender (replication=database) and create a pgoutput
// slot. The Cluster sets allowReplication: logical.
func TestLogicalReplication(t *testing.T) {
	repl := func(client, user, mode, cmd string) (string, error) {
		return psqlDSN(client, fmt.Sprintf(
			"host=%s port=15432 dbname=app user=%s replication=%s sslmode=prefer connect_timeout=10",
			pgppiHost, user, mode), cmd)
	}

	t.Run("cdc creates a logical slot", func(t *testing.T) {
		out, err := repl("cdc", "cdc", "database", "IDENTIFY_SYSTEM")
		if err != nil || !strings.Contains(out, "|app") {
			t.Fatalf("IDENTIFY_SYSTEM: %v: %s", err, out)
		}
		out, err = repl("cdc", "cdc", "database", "CREATE_REPLICATION_SLOT pgppi_e2e TEMPORARY LOGICAL pgoutput")
		if err != nil || !strings.Contains(out, "pgppi_e2e") {
			t.Fatalf("CREATE_REPLICATION_SLOT: %v: %s", err, out)
		}
	})

	for _, tc := range []struct{ name, client, user, mode, want string }{
		{"NOREPLICATION role", "billing", "billing_app", "database", "permission denied"},
		{"identity claims the cdc role", "billing", "cdc", "database", "certificate authentication failed"},
		{"physical is not allowed by the logical policy", "cdc", "cdc", "true", "physical replication connections are not allowed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := repl(tc.client, tc.user, tc.mode, "IDENTIFY_SYSTEM")
			if err == nil {
				t.Fatalf("unexpectedly succeeded: %s", out)
			}
			if !strings.Contains(out, tc.want) {
				t.Errorf("output %q does not contain %q", out, tc.want)
			}
		})
	}
}
