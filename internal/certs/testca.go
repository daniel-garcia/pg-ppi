package certs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// WriteTestCA generates a self-signed CA (ca.crt, ca.key) in dir. If
// serverNames is non-empty it also writes a server certificate signed by
// that CA (server.crt, server.key) valid for those DNS names / IPs. It is
// intended for tests and local experiments only.
func WriteTestCA(dir string, serverNames ...string) error {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pgppi-test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	ca, _ := x509.ParseCertificate(caDER)
	if err := writePair(dir, "ca", caDER, caKey); err != nil {
		return err
	}
	if len(serverNames) == 0 {
		return nil
	}

	srvKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	srvTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: serverNames[0]},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, n := range serverNames {
		if ip := net.ParseIP(n); ip != nil {
			srvTmpl.IPAddresses = append(srvTmpl.IPAddresses, ip)
		} else {
			srvTmpl.DNSNames = append(srvTmpl.DNSNames, n)
		}
	}
	srvDER, err := x509.CreateCertificate(rand.Reader, srvTmpl, ca, &srvKey.PublicKey, caKey)
	if err != nil {
		return err
	}
	return writePair(dir, "server", srvDER, srvKey)
}

func writePair(dir, name string, der []byte, key *ecdsa.PrivateKey) error {
	kder, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, name+".crt"),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	// 0600 so PostgreSQL accepts it as ssl_key_file.
	return os.WriteFile(filepath.Join(dir, name+".key"),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kder}), 0o600)
}
