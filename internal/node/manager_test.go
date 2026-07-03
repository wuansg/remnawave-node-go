package node

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/remnawave/remnawave-node-go/internal/config"
	"github.com/remnawave/remnawave-node-go/internal/coreapi"
	"github.com/remnawave/remnawave-node-go/internal/state"
	"github.com/remnawave/remnawave-node-go/internal/statname"
	"github.com/remnawave/remnawave-node-go/internal/system"
)

type fakeStatsClient struct {
	stats       []coreapi.Stat
	lastPattern string
	lastReset   bool
}

func (f *fakeStatsClient) Query(_ context.Context, pattern string, reset bool) ([]coreapi.Stat, error) {
	f.lastPattern, f.lastReset = pattern, reset
	return f.stats, nil
}
func (f *fakeStatsClient) System(context.Context) (coreapi.SystemStats, error) {
	return coreapi.SystemStats{NumGoroutine: 7, Uptime: 42}, nil
}
func (f *fakeStatsClient) Online(context.Context, string) (bool, error) { return true, nil }
func (f *fakeStatsClient) UserIPs(context.Context, string) (map[string]int64, error) {
	return map[string]int64{"1.1.1.1": 1710000000}, nil
}
func (f *fakeStatsClient) OnlineUsers(context.Context) ([]string, error) {
	return []string{"user-a"}, nil
}
func (f *fakeStatsClient) Close() error { return nil }

func TestShouldRestartCoreIncludesCoreStatusAndConfiguration(t *testing.T) {
	hashes := state.StartHashes{
		EmptyConfig: "base",
		Inbounds:    []state.InboundHash{{Tag: "in", Hash: "users", UsersCount: 1}},
	}
	runtimeState := state.New("test")
	runtimeState.SetRunningCore(state.CoreTypeXRAY)
	runtimeState.SetOnlineStatus(true, false)
	runtimeState.SetLastHashes(hashes)

	manager := &Manager{state: runtimeState}
	if manager.shouldRestartCore(state.CoreTypeXRAY, false, hashes) {
		t.Fatal("unchanged online core should not restart")
	}
	if !manager.shouldRestartCore(state.CoreTypeSingBox, false, hashes) {
		t.Fatal("switching core must restart even when hashes match")
	}

	runtimeState.SetOnlineStatus(false, false)
	if !manager.shouldRestartCore(state.CoreTypeXRAY, false, hashes) {
		t.Fatal("offline core must restart even when hashes match")
	}

	runtimeState.SetOnlineStatus(true, false)
	manager.cfg = config.Config{DisableHashCheck: true}
	if !manager.shouldRestartCore(state.CoreTypeXRAY, false, hashes) {
		t.Fatal("disabled hash checks must force a restart")
	}
}

func TestFormatCoreVersion(t *testing.T) {
	t.Setenv("SING_BOX_VERSION", "v1.13.13")

	tests := []struct {
		name   string
		binary string
		line   string
		want   string
	}{
		{
			name:   "xray long version",
			binary: "/usr/local/bin/xray",
			line:   "Xray 26.3.27 (Xray, Penetrates Everything.) d2758a0 (go1.26.1 linux/amd64)",
			want:   "26.3.27",
		},
		{
			name:   "sing-box explicit version",
			binary: "/usr/local/bin/sing-box",
			line:   "sing-box version 1.13.13",
			want:   "1.13.13",
		},
		{
			name:   "sing-box fallback version",
			binary: "/usr/local/bin/sing-box",
			line:   "sing-box version unknown",
			want:   "1.13.13",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := formatCoreVersion(tt.binary, tt.line); got != tt.want {
				t.Fatalf("formatCoreVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGetUsersStatsUsesCoreStatsAndReset(t *testing.T) {
	encodedUser := statname.UserInbound("user-a", "in-a")
	client := &fakeStatsClient{stats: []coreapi.Stat{
		{Name: "user>>>" + encodedUser + ">>>traffic>>>uplink", Value: 10},
		{Name: "user>>>" + encodedUser + ">>>traffic>>>downlink", Value: 20},
		{Name: "user>>>idle>>>traffic>>>uplink", Value: 0},
	}}
	manager := &Manager{state: state.New("test"), xrayStats: client}
	response := manager.GetUsersStats(context.Background(), GetUsersStatsRequest{Reset: true})
	users := response["response"].(map[string]any)["users"].([]map[string]any)
	if len(users) != 1 || users[0]["username"] != "user-a" || users[0]["uplink"] != int64(10) || users[0]["downlink"] != int64(20) {
		t.Fatalf("unexpected user stats: %#v", users)
	}
	if client.lastPattern != "user>>>" || !client.lastReset {
		t.Fatalf("query did not preserve pattern/reset: %q %v", client.lastPattern, client.lastReset)
	}
}

func TestGetUsersInboundStatsReturnsInboundDimension(t *testing.T) {
	client := &fakeStatsClient{stats: []coreapi.Stat{
		{Name: "user>>>" + statname.UserInbound("user-a", "in-a") + ">>>traffic>>>uplink", Value: 10},
		{Name: "user>>>" + statname.UserInbound("user-a", "in-b") + ">>>traffic>>>downlink", Value: 20},
		{Name: "user>>>legacy-user>>>traffic>>>uplink", Value: 30},
	}}
	manager := &Manager{state: state.New("test"), xrayStats: client}
	response := manager.GetUsersInboundStats(context.Background(), GetUsersInboundStatsRequest{Reset: true})
	users := response["response"].(map[string]any)["users"].([]map[string]any)
	if len(users) != 3 {
		t.Fatalf("unexpected user inbound stats: %#v", users)
	}
	if users[0]["username"] != "legacy-user" || users[0]["inbound"] != "" {
		t.Fatalf("legacy stats should be preserved without an inbound: %#v", users[0])
	}
	if users[1]["username"] != "user-a" || users[1]["inbound"] != "in-a" || users[1]["uplink"] != int64(10) {
		t.Fatalf("unexpected first inbound stat: %#v", users[1])
	}
	if users[2]["username"] != "user-a" || users[2]["inbound"] != "in-b" || users[2]["downlink"] != int64(20) {
		t.Fatalf("unexpected second inbound stat: %#v", users[2])
	}
}

func TestGetInboundStatsAggregatesDirections(t *testing.T) {
	client := &fakeStatsClient{stats: []coreapi.Stat{
		{Name: "inbound>>>edge>>>traffic>>>uplink", Value: 11},
		{Name: "inbound>>>edge>>>traffic>>>downlink", Value: 22},
	}}
	manager := &Manager{state: state.New("test"), xrayStats: client}
	response := manager.GetInboundStats(context.Background(), GetTagStatsRequest{Tag: "edge"})
	item := response["response"].(map[string]any)
	if item["uplink"] != int64(11) || item["downlink"] != int64(22) {
		t.Fatalf("unexpected inbound stats: %#v", item)
	}
}

func TestGetSystemStatsAlwaysIncludesCoreInfo(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := &Manager{
		state:   state.New("test"),
		network: system.NewNetworkMonitor(logger),
	}
	response := manager.GetSystemStats(context.Background())
	xrayInfo := response["response"].(map[string]any)["xrayInfo"]
	stats, ok := xrayInfo.(map[string]any)
	if !ok {
		t.Fatalf("xrayInfo must be an object, got %#v", xrayInfo)
	}
	if stats["uptime"] != 0 || len(stats) != 10 {
		t.Fatalf("unexpected offline core stats: %#v", stats)
	}
}

func TestVisionRuleTagMatchesNodeObjectHash(t *testing.T) {
	if got, want := visionRuleTag("1.2.3.4"), "0af2996736a0258868c61eb7f5151216"; got != want {
		t.Fatalf("vision rule tag = %q, want %q", got, want)
	}
}

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

func TestApplyAddUserRequestKeepsAllRequestedInbounds(t *testing.T) {
	runtimeState := state.New("test")
	runtimeState.SetXrayConfig(map[string]any{"inbounds": []any{
		map[string]any{"tag": "in-a", "protocol": "vless", "settings": map[string]any{"clients": []any{}}},
		map[string]any{"tag": "in-b", "protocol": "vless", "settings": map[string]any{"clients": []any{}}},
	}})
	runtimeState.SetRunningCore(state.CoreTypeXRAY)
	manager := &Manager{state: runtimeState}
	request := AddUserRequest{Data: []AddUserItem{
		{Type: "vless", Tag: "in-a", Username: "user-a", UUID: "uuid-a"},
		{Type: "vless", Tag: "in-b", Username: "user-a", UUID: "uuid-a"},
	}}
	if err := manager.applyAddUserRequest(request); err != nil {
		t.Fatalf("apply add user: %v", err)
	}
	if got := len(runtimeState.InboundUsers("in-a")); got != 1 {
		t.Fatalf("in-a users = %d, want 1", got)
	}
	if got := len(runtimeState.InboundUsers("in-b")); got != 1 {
		t.Fatalf("in-b users = %d, want 1", got)
	}
	xrayConfig := runtimeState.XrayConfig()
	inbounds := asMapSlice(xrayConfig["inbounds"])
	firstSettings := inbounds[0]["settings"].(map[string]any)
	firstClients := asMapSlice(firstSettings["clients"])
	if got, want := stringValue(firstClients[0]["email"]), statname.UserInbound("user-a", "in-a"); got != want {
		t.Fatalf("encoded xray stats username = %q, want %q", got, want)
	}
	if got := runtimeState.InboundUsers("in-a")[0].UserID; got != "user-a" {
		t.Fatalf("runtime inbound user should expose real user id, got %q", got)
	}
}

func TestSingBoxUserConnectionStatsReturnEmpty(t *testing.T) {
	runtimeState := state.New("test")
	runtimeState.SetRunningCore(state.CoreTypeSingBox)
	runtimeState.RecordUserIP("2", "163.125.176.65", time.Unix(1710000000, 0))

	manager := &Manager{state: runtimeState}

	userIPs := manager.GetUserIPList(context.Background(), GetUserIPListRequest{UserID: "2"})
	if got := len(userIPs["response"].(map[string]any)["ips"].([]map[string]any)); got != 0 {
		t.Fatalf("expected sing-box user ip list to be empty, got %d items", got)
	}

	usersIPs := manager.GetUsersIPList(context.Background())
	if got := len(usersIPs["response"].(map[string]any)["users"].([]map[string]any)); got != 0 {
		t.Fatalf("expected sing-box users ip list to be empty, got %d users", got)
	}

	online := manager.GetUserOnlineStatus(context.Background(), GetUserOnlineStatusRequest{Username: "2"})
	if online["response"].(map[string]any)["isOnline"].(bool) {
		t.Fatalf("expected sing-box user online status to be false")
	}
}

func TestXrayUserConnectionStatsUseRecordedIPs(t *testing.T) {
	runtimeState := state.New("test")
	runtimeState.SetRunningCore(state.CoreTypeXRAY)
	runtimeState.RecordUserIP("2", "163.125.176.65", time.Unix(1710000000, 0))

	manager := &Manager{state: runtimeState}

	userIPs := manager.GetUserIPList(context.Background(), GetUserIPListRequest{UserID: "2"})
	if got := len(userIPs["response"].(map[string]any)["ips"].([]map[string]any)); got != 1 {
		t.Fatalf("expected xray user ip list to contain 1 item, got %d", got)
	}

	usersIPs := manager.GetUsersIPList(context.Background())
	if got := len(usersIPs["response"].(map[string]any)["users"].([]map[string]any)); got != 1 {
		t.Fatalf("expected xray users ip list to contain 1 user, got %d", got)
	}
}
