package state

import "testing"

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
