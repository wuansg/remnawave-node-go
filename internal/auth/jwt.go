package auth

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Verifier struct {
	publicKey *rsa.PublicKey
}

func NewVerifier(publicKeyPEM string) (*Verifier, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
	if block == nil {
		return nil, errors.New("jwt public key PEM is invalid")
	}

	if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
		key, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("jwt certificate public key is not RSA")
		}
		return &Verifier{publicKey: key}, nil
	}

	if key, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return &Verifier{publicKey: key}, nil
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("jwt public key is invalid: %w", err)
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("jwt public key is not RSA")
	}
	return &Verifier{publicKey: rsaKey}, nil
}

func (v *Verifier) Verify(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("jwt must have three parts")
	}

	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, errors.New("jwt header is invalid base64url")
	}

	var header struct {
		Algorithm string `json:"alg"`
		Type      string `json:"typ"`
	}
	if err := json.Unmarshal(headerRaw, &header); err != nil {
		return nil, errors.New("jwt header is invalid JSON")
	}
	if header.Algorithm != "RS256" {
		return nil, fmt.Errorf("unsupported jwt algorithm: %s", header.Algorithm)
	}

	signingInput := []byte(parts[0] + "." + parts[1])
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errors.New("jwt signature is invalid base64url")
	}

	digest := sha256.Sum256(signingInput)
	if err := rsa.VerifyPKCS1v15(v.publicKey, crypto.SHA256, digest[:], signature); err != nil {
		return nil, errors.New("jwt signature verification failed")
	}

	payloadRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, errors.New("jwt payload is invalid base64url")
	}

	var claims map[string]any
	if err := json.Unmarshal(payloadRaw, &claims); err != nil {
		return nil, errors.New("jwt payload is invalid JSON")
	}

	now := time.Now().Unix()
	if exp, ok := numericClaim(claims["exp"]); ok && now >= exp {
		return nil, errors.New("jwt expired")
	}
	if nbf, ok := numericClaim(claims["nbf"]); ok && now < nbf {
		return nil, errors.New("jwt not active yet")
	}

	return claims, nil
}

func numericClaim(value any) (int64, bool) {
	switch typed := value.(type) {
	case float64:
		return int64(typed), true
	case int64:
		return typed, true
	default:
		return 0, false
	}
}
