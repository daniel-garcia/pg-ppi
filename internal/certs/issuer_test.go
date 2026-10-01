package certs

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"
)

const identity = "billing.billing.serviceaccount.identity.linkerd.cluster.local"

func newTestIssuer(t *testing.T) (*Issuer, string) {
	t.Helper()
	dir := t.TempDir()
	if err := WriteTestCA(dir); err != nil {
		t.Fatal(err)
	}
	i, err := NewIssuer(filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key"), time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return i, dir
}

func TestClientCertificate(t *testing.T) {
	i, dir := newTestIssuer(t)

	c, err := i.ClientCertificate(identity)
	if err != nil {
		t.Fatal(err)
	}
	if c.Leaf.Subject.CommonName != identity {
		t.Errorf("CN = %q", c.Leaf.Subject.CommonName)
	}

	caPEM, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(caPEM)
	if _, err := c.Leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("leaf does not verify against CA: %v", err)
	}

	again, _ := i.ClientCertificate(identity)
	if again != c {
		t.Error("expected cached certificate")
	}
	other, _ := i.ClientCertificate("reporting.billing.serviceaccount.identity.linkerd.cluster.local")
	if other == c {
		t.Error("expected distinct certificate per identity")
	}
}

func TestClientCertificateRenewal(t *testing.T) {
	i, _ := newTestIssuer(t)
	base := time.Now()
	i.now = func() time.Time { return base }

	c1, _ := i.ClientCertificate(identity)
	i.now = func() time.Time { return base.Add(50 * time.Minute) }
	c2, _ := i.ClientCertificate(identity)
	if c1 == c2 {
		t.Error("expected renewal once less than ttl/3 remains")
	}
}

func TestCAReload(t *testing.T) {
	i, dir := newTestIssuer(t)
	c1, _ := i.ClientCertificate(identity)

	if err := WriteTestCA(dir); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Minute)
	for _, f := range []string{"ca.crt", "ca.key"} {
		_ = os.Chtimes(filepath.Join(dir, f), future, future)
	}

	c2, err := i.ClientCertificate(identity)
	if err != nil {
		t.Fatal(err)
	}
	if c1 == c2 || string(c1.Leaf.AuthorityKeyId) == string(c2.Leaf.AuthorityKeyId) {
		t.Error("expected certificate from rotated CA")
	}
}
