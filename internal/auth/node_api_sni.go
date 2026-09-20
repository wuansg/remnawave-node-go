package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

const (
	nodeAPISNIPrefix = "rw-"
	nodeAPISNISuffix = ".node.invalid"
)

func DeriveNodeAPIServerName(caCertPEM, jwtPublicKeyPEM string) (string, error) {
	caBlock, _ := pem.Decode([]byte(caCertPEM))
	if caBlock == nil {
		return "", errors.New("CA certificate is not valid PEM")
	}
	caCertificate, err := x509.ParseCertificate(caBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse CA certificate: %w", err)
	}

	publicKeyBlock, _ := pem.Decode([]byte(jwtPublicKeyPEM))
	if publicKeyBlock == nil {
		return "", errors.New("JWT public key is not valid PEM")
	}
	publicKey, err := parsePublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return "", fmt.Errorf("parse JWT public key: %w", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return "", fmt.Errorf("marshal JWT public key: %w", err)
	}

	digest := sha256.New()
	_, _ = digest.Write(caCertificate.Raw)
	_, _ = digest.Write(publicKeyDER)
	return nodeAPISNIPrefix + hex.EncodeToString(digest.Sum(nil)) + nodeAPISNISuffix, nil
}

func NodeAPIServerNameMatches(expected, actual string) bool {
	expectedDigest := sha256.Sum256([]byte(normalizeServerName(expected)))
	actualDigest := sha256.Sum256([]byte(normalizeServerName(actual)))
	return subtle.ConstantTimeCompare(expectedDigest[:], actualDigest[:]) == 1
}

func parsePublicKey(der []byte) (any, error) {
	publicKey, err := x509.ParsePKIXPublicKey(der)
	if err == nil {
		return publicKey, nil
	}
	if rsaPublicKey, rsaErr := x509.ParsePKCS1PublicKey(der); rsaErr == nil {
		return rsaPublicKey, nil
	}
	return nil, err
}

func normalizeServerName(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}
