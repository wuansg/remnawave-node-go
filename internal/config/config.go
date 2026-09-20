package config

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
)

const defaultVersion = "3.13.0"

var buildVersion = defaultVersion

type Config struct {
	NodePort              int
	SecretKey             string
	DisableHashCheck      bool
	SingBoxAPIPort        int
	SingBoxV2RayAPIPort   int
	InternalRESTToken     string
	InternalSocketPath    string
	SupervisordSocket     string
	SupervisordPIDPath    string
	SupervisordUser       string
	SupervisordPass       string
	SingBoxConfigPath     string
	SingBoxBinaryPath     string
	SingBoxLastGoodPath   string
	NodePayload           NodePayload
	NodeVersion           string
	UsageSnapshotDBPath   string
	UsageSnapshotInterval int
	UsageSnapshotMaxBytes int64
	ForwardingStatePath   string
	NodeAPISNIEnabled     bool
}

type NodePayload struct {
	CACertPEM    string `json:"caCertPem"`
	JWTPublicKey string `json:"jwtPublicKey"`
	NodeCertPEM  string `json:"nodeCertPem"`
	NodeKeyPEM   string `json:"nodeKeyPem"`
}

func Load() (Config, error) {
	secret := normalizeSecret(os.Getenv("SECRET_KEY"))
	if secret == "" {
		return Config{}, errors.New("SECRET_KEY is required")
	}

	payload, err := ParseNodePayload(secret)
	if err != nil {
		return Config{}, err
	}

	return Config{
		NodePort:              envInt("NODE_PORT", 2222),
		SecretKey:             secret,
		DisableHashCheck:      envBool("DISABLE_HASHED_SET_CHECK", false),
		SingBoxAPIPort:        envInt("SING_BOX_API_PORT", 61001),
		SingBoxV2RayAPIPort:   envInt("SING_BOX_V2RAY_API_PORT", 61002),
		InternalRESTToken:     os.Getenv("INTERNAL_REST_TOKEN"),
		InternalSocketPath:    envString("INTERNAL_SOCKET_PATH", "/run/remnawave/internal.sock"),
		SupervisordSocket:     os.Getenv("SUPERVISORD_SOCKET_PATH"),
		SupervisordPIDPath:    os.Getenv("SUPERVISORD_PID_PATH"),
		SupervisordUser:       os.Getenv("SUPERVISORD_USER"),
		SupervisordPass:       os.Getenv("SUPERVISORD_PASSWORD"),
		SingBoxConfigPath:     envString("SING_BOX_CONFIG_PATH", "/run/remnawave/sing-box.json"),
		SingBoxBinaryPath:     envString("SING_BOX_BINARY_PATH", "/usr/local/bin/sing-box"),
		SingBoxLastGoodPath:   envString("SING_BOX_LAST_GOOD_CONFIG_PATH", "/var/lib/remnanode/sing-box.last-good.json"),
		NodePayload:           payload,
		NodeVersion:           detectVersion(),
		UsageSnapshotDBPath:   envString("USAGE_SNAPSHOT_DB_PATH", "/var/lib/remnanode/stats.db"),
		UsageSnapshotInterval: envInt("USAGE_SNAPSHOT_INTERVAL_SECONDS", 10),
		UsageSnapshotMaxBytes: int64(envInt("USAGE_SNAPSHOT_MAX_MIB", 256)) << 20,
		ForwardingStatePath:   envString("FORWARDING_STATE_PATH", "/var/lib/remnanode/forwarding.json"),
		NodeAPISNIEnabled:     envBool("NODE_API_SNI_ENABLED", false),
	}, nil
}

func ParseNodePayload(encoded string) (NodePayload, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return NodePayload{}, fmt.Errorf("SECRET_KEY is not valid base64: %w", err)
	}

	var payload NodePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return NodePayload{}, fmt.Errorf("SECRET_KEY contains invalid JSON: %w", err)
	}

	payload.CACertPEM = normalizePEM(payload.CACertPEM)
	payload.JWTPublicKey = normalizePEM(payload.JWTPublicKey)
	payload.NodeCertPEM = normalizePEM(payload.NodeCertPEM)
	payload.NodeKeyPEM = normalizePEM(payload.NodeKeyPEM)

	if payload.CACertPEM == "" || payload.JWTPublicKey == "" || payload.NodeCertPEM == "" || payload.NodeKeyPEM == "" {
		return NodePayload{}, errors.New("SECRET_KEY payload is missing required PEM fields")
	}

	for name, value := range map[string]string{
		"caCertPem":    payload.CACertPEM,
		"jwtPublicKey": payload.JWTPublicKey,
		"nodeCertPem":  payload.NodeCertPEM,
		"nodeKeyPem":   payload.NodeKeyPEM,
	} {
		block, _ := pem.Decode([]byte(value))
		if block == nil {
			return NodePayload{}, fmt.Errorf("%s is not valid PEM", name)
		}
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM([]byte(payload.CACertPEM)) {
		return NodePayload{}, errors.New("caCertPem is not a valid certificate pool")
	}

	return payload, nil
}

func normalizePEM(value string) string {
	value = strings.ReplaceAll(value, "\\n", "\n")
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.TrimSpace(value)
	return value
}

func normalizeSecret(value string) string {
	value = strings.TrimSpace(value)
	return strings.Trim(value, "\"")
}

func envString(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func envBool(key string, fallback bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return fallback
	}
	return value == "true" || value == "1"
}

func detectVersion() string {
	if value := strings.TrimSpace(os.Getenv("REMNAWAVE_NODE_VERSION")); value != "" {
		return value
	}
	if value := strings.TrimSpace(buildVersion); value != "" {
		return value
	}
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "" && info.Main.Version != "(devel)" {
		return info.Main.Version
	}
	return defaultVersion
}
