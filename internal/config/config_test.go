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
