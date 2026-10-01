// Package certs mints short-lived client certificates whose Common Name is a
// Linkerd workload identity. PostgreSQL's `cert` authentication then maps
// that CN to a database role through pg_ident.conf, so the database (not
// this sidecar) remains the policy decision point.
package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"sync"
	"time"
)

// Issuer signs client certificates with a CA that PostgreSQL trusts for
// client authentication (CloudNativePG's client CA, i.e. ssl_ca_file).
type Issuer struct {
	certFile, keyFile string
	ttl               time.Duration
	now               func() time.Time

	mu      sync.Mutex
	caMod   time.Time
	ca      *x509.Certificate
	caKey   crypto.Signer
	cache   map[string]*tls.Certificate
	leafKey *ecdsa.PrivateKey
}

// NewIssuer loads the CA from PEM files. The files are re-read whenever
// their modification time changes, so a rotated Kubernetes Secret is picked
// up without a restart.
func NewIssuer(certFile, keyFile string, ttl time.Duration) (*Issuer, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	i := &Issuer{
		certFile: certFile,
		keyFile:  keyFile,
		ttl:      ttl,
		now:      time.Now,
		cache:    map[string]*tls.Certificate{},
		leafKey:  key,
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if err := i.reloadLocked(); err != nil {
		return nil, err
	}
	return i, nil
}

// ClientCertificate returns a certificate with CN=identity, minting (and
// caching) one if needed. Cached certificates are reused until less than a
// third of their lifetime remains.
func (i *Issuer) ClientCertificate(identity string) (*tls.Certificate, error) {
	i.mu.Lock()
	defer i.mu.Unlock()

	if err := i.reloadLocked(); err != nil {
		return nil, err
	}
	now := i.now()
	if c, ok := i.cache[identity]; ok && c.Leaf.NotAfter.Sub(now) > i.ttl/3 {
		return c, nil
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: identity},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(i.ttl),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, i.ca, &i.leafKey.PublicKey, i.caKey)
	if err != nil {
		return nil, fmt.Errorf("signing client certificate for %q: %w", identity, err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  i.leafKey,
		Leaf:        leaf,
	}
	i.cache[identity] = c
	return c, nil
}

func (i *Issuer) reloadLocked() error {
	st, err := os.Stat(i.certFile)
	if err != nil {
		return err
	}
	if kst, err := os.Stat(i.keyFile); err != nil {
		return err
	} else if kst.ModTime().After(st.ModTime()) {
		st = kst
	}
	if i.ca != nil && !st.ModTime().After(i.caMod) {
		return nil
	}

	certPEM, err := os.ReadFile(i.certFile)
	if err != nil {
		return err
	}
	keyPEM, err := os.ReadFile(i.keyFile)
	if err != nil {
		return err
	}
	ca, key, err := parseCA(certPEM, keyPEM)
	if err != nil {
		return err
	}
	i.ca, i.caKey, i.caMod = ca, key, st.ModTime()
	clear(i.cache)
	return nil
}

func parseCA(certPEM, keyPEM []byte) (*x509.Certificate, crypto.Signer, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return nil, nil, errors.New("CA certificate: no CERTIFICATE PEM block")
	}
	ca, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("CA certificate: %w", err)
	}
	if !ca.IsCA {
		return nil, nil, errors.New("CA certificate: not a CA")
	}

	kb, _ := pem.Decode(keyPEM)
	if kb == nil {
		return nil, nil, errors.New("CA key: no PEM block")
	}
	var key any
	switch kb.Type {
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(kb.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(kb.Bytes)
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(kb.Bytes)
	default:
		err = fmt.Errorf("unsupported PEM block %q", kb.Type)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("CA key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, nil, errors.New("CA key: not a signing key")
	}
	return ca, signer, nil
}
