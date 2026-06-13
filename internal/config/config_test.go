package config

import "testing"

func TestNormalizeSecret(t *testing.T) {
	t.Parallel()

	if got := normalizeSecret(` "quoted-secret" `); got != "quoted-secret" {
		t.Fatalf("normalizeSecret() = %q, want %q", got, "quoted-secret")
	}

	if got := normalizeSecret("plain-secret"); got != "plain-secret" {
		t.Fatalf("normalizeSecret() = %q, want %q", got, "plain-secret")
	}
}

func TestDetectVersionUsesEnvOverride(t *testing.T) {
	t.Setenv("REMNAWAVE_NODE_VERSION", "2.7.1")

	if got := detectVersion(); got != "2.7.1" {
		t.Fatalf("detectVersion() = %q, want %q", got, "2.7.1")
	}
}

func TestDetectVersionFallsBackToBuildVersion(t *testing.T) {
	t.Setenv("REMNAWAVE_NODE_VERSION", "")

	original := buildVersion
	buildVersion = "2.7.0"
	t.Cleanup(func() {
		buildVersion = original
	})

	if got := detectVersion(); got != "2.7.0" {
		t.Fatalf("detectVersion() = %q, want %q", got, "2.7.0")
	}
}
