package node

import (
	"testing"
	"time"

	"github.com/remnawave/remnawave-node-go/internal/state"
)

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

func TestSingBoxUserConnectionStatsReturnEmpty(t *testing.T) {
	runtimeState := state.New("test")
	runtimeState.SetRunningCore(state.CoreTypeSingBox)
	runtimeState.RecordUserIP("2", "163.125.176.65", time.Unix(1710000000, 0))

	manager := &Manager{state: runtimeState}

	userIPs := manager.GetUserIPList(GetUserIPListRequest{UserID: "2"})
	if got := len(userIPs["response"].(map[string]any)["ips"].([]map[string]any)); got != 0 {
		t.Fatalf("expected sing-box user ip list to be empty, got %d items", got)
	}

	usersIPs := manager.GetUsersIPList()
	if got := len(usersIPs["response"].(map[string]any)["users"].([]map[string]any)); got != 0 {
		t.Fatalf("expected sing-box users ip list to be empty, got %d users", got)
	}

	online := manager.GetUserOnlineStatus(GetUserOnlineStatusRequest{Username: "2"})
	if online["response"].(map[string]any)["isOnline"].(bool) {
		t.Fatalf("expected sing-box user online status to be false")
	}
}

func TestXrayUserConnectionStatsUseRecordedIPs(t *testing.T) {
	runtimeState := state.New("test")
	runtimeState.SetRunningCore(state.CoreTypeXRAY)
	runtimeState.RecordUserIP("2", "163.125.176.65", time.Unix(1710000000, 0))

	manager := &Manager{state: runtimeState}

	userIPs := manager.GetUserIPList(GetUserIPListRequest{UserID: "2"})
	if got := len(userIPs["response"].(map[string]any)["ips"].([]map[string]any)); got != 1 {
		t.Fatalf("expected xray user ip list to contain 1 item, got %d", got)
	}

	usersIPs := manager.GetUsersIPList()
	if got := len(usersIPs["response"].(map[string]any)["users"].([]map[string]any)); got != 1 {
		t.Fatalf("expected xray users ip list to contain 1 user, got %d", got)
	}
}
