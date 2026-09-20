package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestDeriveNodeAPIServerNameIsStable(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	certificateDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificateDER})
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER})

	first, err := DeriveNodeAPIServerName(string(caPEM), string(publicKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	second, err := DeriveNodeAPIServerName(string(caPEM), string(publicKeyPEM))
	if err != nil {
		t.Fatal(err)
	}
	if first != second {
		t.Fatalf("derived names differ: %q and %q", first, second)
	}
	if !strings.HasPrefix(first, "rw-") || !strings.HasSuffix(first, ".node.invalid") || len(first) != 80 {
		t.Fatalf("unexpected derived server name %q", first)
	}
	if !NodeAPIServerNameMatches(first, strings.ToUpper(first)+".") {
		t.Fatal("server name comparison should be DNS case-insensitive")
	}
	if NodeAPIServerNameMatches(first, "wrong.node.invalid") {
		t.Fatal("incorrect server name unexpectedly matched")
	}
}
