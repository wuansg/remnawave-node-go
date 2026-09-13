package state

import (
	"testing"
	"time"
)

func TestSingBoxProtocolsAreIndexed(t *testing.T) {
	runtimeState := New("test")
	runtimeState.SetSingBoxConfig(map[string]any{
		"inbounds": []any{
			map[string]any{
				"tag":  "anytls-in",
				"type": "anytls",
				"users": []any{
					map[string]any{"name": "101", "password": "secret"},
				},
			},
			map[string]any{
				"tag":  "hy2-in",
				"type": "hysteria2",
				"users": []any{
					map[string]any{"name": "102", "password": "uuid-102"},
				},
			},
			map[string]any{
				"tag":  "tuic-in",
				"type": "tuic",
				"users": []any{
					map[string]any{"name": "103", "uuid": "uuid-103", "password": "pw-103"},
				},
			},
		},
	})
	runtimeState.SetRunningCore(CoreTypeSingBox)

	assertIndexedUser(t, runtimeState, "anytls-in", "101", "anytls")
	assertIndexedUser(t, runtimeState, "hy2-in", "102", "hysteria2")
	assertIndexedUser(t, runtimeState, "tuic-in", "103", "tuic")
}

func assertIndexedUser(t *testing.T, runtimeState *Runtime, tag, userID, protocol string) {
	t.Helper()
	users := runtimeState.InboundUsers(tag)
	if len(users) != 1 {
		t.Fatalf("expected one user for %s, got %d", tag, len(users))
	}
	if users[0].UserID != userID {
		t.Fatalf("expected user %s for %s, got %s", userID, tag, users[0].UserID)
	}
	if users[0].Protocol != protocol {
		t.Fatalf("expected protocol %s for %s, got %s", protocol, tag, users[0].Protocol)
	}
}

func TestPluginDomainResolutionStateIsDeepCloned(t *testing.T) {
	now := time.Now().UTC()
	runtimeState := New("test")
	runtimeState.SetPluginState(PluginState{
		DomainResolutions: map[string]DomainResolution{
			"example.com": {
				Domain:        "example.com",
				Addresses:     []string{"192.0.2.1"},
				LastAttemptAt: &now,
				LastSuccessAt: &now,
			},
		},
	})

	read := runtimeState.PluginState()
	item := read.DomainResolutions["example.com"]
	item.Addresses[0] = "198.51.100.1"
	item.LastSuccessAt = nil
	read.DomainResolutions["example.com"] = item

	stored := runtimeState.PluginState().DomainResolutions["example.com"]
	if stored.Addresses[0] != "192.0.2.1" {
		t.Fatalf("stored address was mutated through returned state: %q", stored.Addresses[0])
	}
	if stored.LastSuccessAt == nil {
		t.Fatal("stored success timestamp was mutated through returned state")
	}
}
