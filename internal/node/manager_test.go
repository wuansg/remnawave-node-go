package node

import "testing"

func TestAddSingBoxUserSupportsAnyTLSHy2AndTUIC(t *testing.T) {
	config := map[string]any{
		"inbounds": []any{
			map[string]any{"tag": "anytls", "type": "anytls", "users": []any{}},
			map[string]any{"tag": "hy2", "type": "hysteria2", "users": []any{}},
			map[string]any{"tag": "tuic", "type": "tuic", "users": []any{}},
		},
	}

	if err := addSingBoxUser(config, AddUserItem{
		Tag:      "anytls",
		Username: "1001",
		Password: "anytls-password",
	}); err != nil {
		t.Fatalf("failed to add anytls user: %v", err)
	}
	if err := addSingBoxUser(config, AddUserItem{
		Tag:      "hy2",
		Username: "1002",
		Password: "uuid-1002",
	}); err != nil {
		t.Fatalf("failed to add hysteria2 user: %v", err)
	}
	if err := addSingBoxUser(config, AddUserItem{
		Tag:      "tuic",
		Username: "1003",
		UUID:     "uuid-1003",
		Password: "trojan-password",
	}); err != nil {
		t.Fatalf("failed to add tuic user: %v", err)
	}

	anytlsUsers := asMapSlice(asMapSlice(config["inbounds"])[0]["users"])
	hy2Users := asMapSlice(asMapSlice(config["inbounds"])[1]["users"])
	tuicUsers := asMapSlice(asMapSlice(config["inbounds"])[2]["users"])

	if got := stringValue(anytlsUsers[0]["password"]); got != "anytls-password" {
		t.Fatalf("unexpected anytls password: %s", got)
	}
	if got := stringValue(hy2Users[0]["password"]); got != "uuid-1002" {
		t.Fatalf("unexpected hysteria2 password: %s", got)
	}
	if got := stringValue(tuicUsers[0]["uuid"]); got != "uuid-1003" {
		t.Fatalf("unexpected tuic uuid: %s", got)
	}
	if got := stringValue(tuicUsers[0]["password"]); got != "trojan-password" {
		t.Fatalf("unexpected tuic password: %s", got)
	}
}
