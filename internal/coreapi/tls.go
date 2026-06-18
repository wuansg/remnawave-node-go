package coreapi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"google.golang.org/grpc/credentials"
)

const InternalServerName = "internal.remnawave.local"

type MTLSBundle struct {
	CACertPEM     string
	ServerCertPEM string
	ServerKeyPEM  string
	clientCert    tls.Certificate
}

func GenerateMTLSBundle() (*MTLSBundle, error) {
	now := time.Now().Add(-time.Minute)
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Remnawave Internal CA"},
		NotBefore:             now,
		NotAfter:              now.AddDate(10, 0, 0),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	serverCert, serverCertPEM, serverKeyPEM, err := issueCertificate(caTemplate, caKey, caDER, 2, true, now)
	if err != nil {
		return nil, err
	}
	_ = serverCert
	clientCert, _, _, err := issueCertificate(caTemplate, caKey, caDER, 3, false, now)
	if err != nil {
		return nil, err
	}

	return &MTLSBundle{
		CACertPEM:     string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		ServerCertPEM: serverCertPEM,
		ServerKeyPEM:  serverKeyPEM,
		clientCert:    clientCert,
	}, nil
}

func issueCertificate(ca *x509.Certificate, caKey *rsa.PrivateKey, caDER []byte, serial int64, server bool, now time.Time) (tls.Certificate, string, string, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, "", "", err
	}
	extended := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	dnsNames := []string(nil)
	if server {
		extended = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		dnsNames = []string{InternalServerName}
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: InternalServerName},
		DNSNames:     dnsNames,
		NotBefore:    now,
		NotAfter:     now.AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  extended,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca, &key.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, "", "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, "", "", err
	}
	_ = caDER
	return cert, string(certPEM), string(keyPEM), nil
}

func (b *MTLSBundle) ClientCredentials() (credentials.TransportCredentials, error) {
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(b.CACertPEM)) {
		return nil, fmt.Errorf("append internal CA certificate")
	}
	return credentials.NewTLS(&tls.Config{
		RootCAs:      roots,
		Certificates: []tls.Certificate{b.clientCert},
		ServerName:   InternalServerName,
		MinVersion:   tls.VersionTLS12,
	}), nil
}
