package node

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/remnawave/remnawave-node-go/internal/config"
	"github.com/remnawave/remnawave-node-go/internal/coreapi"
	"github.com/remnawave/remnawave-node-go/internal/state"
	"github.com/remnawave/remnawave-node-go/internal/statname"
	"github.com/remnawave/remnawave-node-go/internal/supervisor"
	"github.com/remnawave/remnawave-node-go/internal/system"
	"github.com/remnawave/remnawave-node-go/internal/usagesnapshot"
)

type fakeStatsClient struct {
	stats       []coreapi.Stat
	lastPattern string
	lastReset   bool
	systemErr   error
	queryCalls  int
}

func (f *fakeStatsClient) Query(_ context.Context, pattern string, reset bool) ([]coreapi.Stat, error) {
	f.queryCalls++
	f.lastPattern, f.lastReset = pattern, reset
	return f.stats, nil
}
func (f *fakeStatsClient) System(context.Context) (coreapi.SystemStats, error) {
	return coreapi.SystemStats{NumGoroutine: 7, Uptime: 42}, f.systemErr
}
func (f *fakeStatsClient) Online(context.Context, string) (bool, error) { return true, nil }
func (f *fakeStatsClient) UserIPs(context.Context, string) (map[string]int64, error) {
	return map[string]int64{"1.1.1.1": 1710000000}, nil
}
func (f *fakeStatsClient) OnlineUsers(context.Context) ([]string, error) {
	return []string{"user-a"}, nil
}
func (f *fakeStatsClient) Close() error { return nil }

type fakeProcessSupervisor struct {
	states      map[string]int
	starts      []string
	stops       []string
	startErrors []error
}

func newFakeProcessSupervisor() *fakeProcessSupervisor {
	return &fakeProcessSupervisor{states: map[string]int{
		singBoxProcessName: supervisor.StateStopped,
	}}
}

func (f *fakeProcessSupervisor) StartProcess(_ context.Context, name string) error {
	f.starts = append(f.starts, name)
	if len(f.startErrors) > 0 {
		err := f.startErrors[0]
		f.startErrors = f.startErrors[1:]
		if err != nil {
			f.states[name] = supervisor.StateFatal
			return err
		}
	}
	f.states[name] = supervisor.StateRunning
	return nil
}

func (f *fakeProcessSupervisor) StopProcess(_ context.Context, name string) error {
	f.stops = append(f.stops, name)
	f.states[name] = supervisor.StateStopped
	return nil
}

func (f *fakeProcessSupervisor) GetProcessInfo(_ context.Context, name string) (supervisor.ProcessInfo, error) {
	stateValue := f.states[name]
	stateName := "STOPPED"
	if stateValue == supervisor.StateRunning {
		stateName = "RUNNING"
	} else if stateValue == supervisor.StateFatal {
		stateName = "FATAL"
	}
	return supervisor.ProcessInfo{Name: name, State: stateValue, StateName: stateName}, nil
}

func TestRestartSingBoxRejectsInvalidCandidateWithoutStoppingCurrentCore(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "sing-box.json")
	lastGoodPath := filepath.Join(dir, "sing-box.last-good.json")
	oldBytes := []byte(`{"inbounds":[{"tag":"old","type":"anytls"}]}`)
	if err := os.WriteFile(configPath, oldBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	oldConfig := map[string]any{"inbounds": []any{map[string]any{"tag": "old", "type": "anytls"}}}
	runtimeState := state.New("test")
	runtimeState.SetSingBoxConfig(oldConfig)
	runtimeState.SetRunningCore(state.CoreTypeSingBox)
	runtimeState.SetOnlineStatus(true)
	// Dynamic user updates mutate runtime state before restarting the core. The
	// rollback path must recover the actual running configuration from disk.
	runtimeState.SetSingBoxConfig(map[string]any{"inbounds": []any{map[string]any{"tag": "new", "type": "anytls"}}})
	fakeSupervisor := newFakeProcessSupervisor()
	fakeSupervisor.states[singBoxProcessName] = supervisor.StateRunning
	manager := &Manager{
		cfg: config.Config{
			SingBoxConfigPath:   configPath,
			SingBoxLastGoodPath: lastGoodPath,
			SingBoxV2RayAPIPort: 61002,
		},
		state:      runtimeState,
		supervisor: fakeSupervisor,
		singStats:  &fakeStatsClient{},
		runCommand: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("parse error at inbounds[0]"), errors.New("exit status 1")
		},
	}

	err := manager.restartSingBox(context.Background(), map[string]any{
		"inbounds": []any{map[string]any{"tag": "new", "type": "anytls"}},
	})
	if err == nil || !strings.Contains(err.Error(), "configuration preflight failed") || !strings.Contains(err.Error(), "parse error") {
		t.Fatalf("unexpected preflight error: %v", err)
	}
	gotBytes, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(gotBytes) != string(oldBytes) {
		t.Fatalf("live configuration changed after preflight failure: %s", gotBytes)
	}
	if len(fakeSupervisor.stops) != 0 || len(fakeSupervisor.starts) != 0 {
		t.Fatalf("preflight failure touched processes: stops=%v starts=%v", fakeSupervisor.stops, fakeSupervisor.starts)
	}
	if got := stringValue(asMapSlice(runtimeState.SingBoxConfig()["inbounds"])[0]["tag"]); got != "old" {
		t.Fatalf("runtime configuration changed after preflight failure: %q", got)
	}
	if manager.singBoxApplyResult["status"] != "REJECTED" || manager.singBoxApplyResult["rollback"] != "NOT_REQUIRED" {
		t.Fatalf("unexpected rejected apply metadata: %#v", manager.singBoxApplyResult)
	}
	if manager.singBoxApplyResult["activeHash"] == manager.singBoxApplyResult["requestedHash"] {
		t.Fatalf("rejected config must not become active: %#v", manager.singBoxApplyResult)
	}
}

func TestRestartSingBoxCommitsCandidateAndLastKnownGood(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "sing-box.json")
	lastGoodPath := filepath.Join(dir, "sing-box.last-good.json")
	if err := os.WriteFile(configPath, []byte(`{"inbounds":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	runtimeState := state.New("test")
	runtimeState.SetSingBoxConfig(map[string]any{"inbounds": []any{}})
	runtimeState.SetRunningCore(state.CoreTypeSingBox)
	runtimeState.SetOnlineStatus(true)
	fakeSupervisor := newFakeProcessSupervisor()
	fakeSupervisor.states[singBoxProcessName] = supervisor.StateRunning
	manager := &Manager{
		cfg: config.Config{
			SingBoxConfigPath:   configPath,
			SingBoxLastGoodPath: lastGoodPath,
			SingBoxV2RayAPIPort: 61002,
		},
		state:              runtimeState,
		supervisor:         fakeSupervisor,
		singStats:          &fakeStatsClient{},
		runCommand:         func(context.Context, string, ...string) ([]byte, error) { return nil, nil },
		healthTimeout:      100 * time.Millisecond,
		healthPollInterval: time.Millisecond,
	}

	if err := manager.restartSingBox(context.Background(), map[string]any{
		"inbounds": []any{map[string]any{"tag": "new", "type": "anytls", "users": []any{}}},
	}); err != nil {
		t.Fatalf("restartSingBox() error = %v", err)
	}
	liveBytes, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	lastGoodBytes, err := os.ReadFile(lastGoodPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(liveBytes) != string(lastGoodBytes) {
		t.Fatalf("last-known-good does not match active config\nlive=%s\nlast-good=%s", liveBytes, lastGoodBytes)
	}
	if got := stringValue(asMapSlice(runtimeState.SingBoxConfig()["inbounds"])[0]["tag"]); got != "new" {
		t.Fatalf("runtime configuration was not committed: %q", got)
	}
	if runtimeState.RunningCoreType() != state.CoreTypeSingBox {
		t.Fatalf("running core = %q, want SING_BOX", runtimeState.RunningCoreType())
	}
	if manager.singBoxApplyResult["status"] != "APPLIED" || manager.singBoxApplyResult["activeHash"] != manager.singBoxApplyResult["requestedHash"] || manager.singBoxApplyResult["appliedAt"] == nil {
		t.Fatalf("unexpected successful apply metadata: %#v", manager.singBoxApplyResult)
	}
}

func TestRestartSingBoxRollsBackAfterHealthFailure(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "sing-box.json")
	lastGoodPath := filepath.Join(dir, "sing-box.last-good.json")
	oldBytes := []byte(`{"inbounds":[{"tag":"old","type":"anytls"}]}`)
	if err := os.WriteFile(configPath, oldBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	oldConfig := map[string]any{"inbounds": []any{map[string]any{"tag": "old", "type": "anytls"}}}
	runtimeState := state.New("test")
	runtimeState.SetSingBoxConfig(oldConfig)
	runtimeState.SetRunningCore(state.CoreTypeSingBox)
	runtimeState.SetOnlineStatus(true)
	runtimeState.SetSingBoxConfig(map[string]any{"inbounds": []any{map[string]any{"tag": "new", "type": "anytls"}}})
	fakeSupervisor := newFakeProcessSupervisor()
	fakeSupervisor.states[singBoxProcessName] = supervisor.StateRunning
	manager := &Manager{
		cfg: config.Config{
			SingBoxConfigPath:   configPath,
			SingBoxLastGoodPath: lastGoodPath,
			SingBoxV2RayAPIPort: 61002,
		},
		state:              runtimeState,
		supervisor:         fakeSupervisor,
		singStats:          &fakeStatsClient{systemErr: errors.New("connection refused")},
		runCommand:         func(context.Context, string, ...string) ([]byte, error) { return nil, nil },
		healthTimeout:      10 * time.Millisecond,
		healthPollInterval: time.Millisecond,
	}

	err := manager.restartSingBox(context.Background(), map[string]any{
		"inbounds": []any{map[string]any{"tag": "new", "type": "anytls"}},
	})
	if err == nil || !strings.Contains(err.Error(), "failed health confirmation") || !strings.Contains(err.Error(), "previous configuration and core restored") {
		t.Fatalf("unexpected activation error: %v", err)
	}
	gotBytes, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(gotBytes) != string(oldBytes) {
		t.Fatalf("live configuration was not rolled back: %s", gotBytes)
	}
	lastGoodBytes, readErr := os.ReadFile(lastGoodPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(lastGoodBytes) != string(oldBytes) {
		t.Fatalf("last-known-good was not preserved: %s", lastGoodBytes)
	}
	if got := stringValue(asMapSlice(runtimeState.SingBoxConfig()["inbounds"])[0]["tag"]); got != "old" {
		t.Fatalf("runtime configuration was not rolled back: %q", got)
	}
	if len(fakeSupervisor.starts) != 2 || fakeSupervisor.starts[0] != singBoxProcessName || fakeSupervisor.starts[1] != singBoxProcessName {
		t.Fatalf("expected activation and rollback starts, got %v", fakeSupervisor.starts)
	}
	if manager.singBoxApplyResult["status"] != "ROLLED_BACK" || manager.singBoxApplyResult["rollback"] != "SUCCEEDED" {
		t.Fatalf("unexpected rollback apply metadata: %#v", manager.singBoxApplyResult)
	}
}

func TestShouldRestartCoreIncludesCoreStatusAndConfiguration(t *testing.T) {
	hashes := state.StartHashes{
		EmptyConfig: "base",
		Inbounds:    []state.InboundHash{{Tag: "in", Hash: "users", UsersCount: 1}},
	}
	runtimeState := state.New("test")
	runtimeState.SetRunningCore(state.CoreTypeSingBox)
	runtimeState.SetOnlineStatus(true)
	runtimeState.SetLastHashes(hashes)

	manager := &Manager{state: runtimeState}
	if manager.shouldRestartCore(state.CoreTypeSingBox, false, hashes) {
		t.Fatal("unchanged online core should not restart")
	}

	runtimeState.SetOnlineStatus(false)
	if !manager.shouldRestartCore(state.CoreTypeSingBox, false, hashes) {
		t.Fatal("offline core must restart even when hashes match")
	}

	runtimeState.SetOnlineStatus(true)
	manager.cfg = config.Config{DisableHashCheck: true}
	if !manager.shouldRestartCore(state.CoreTypeSingBox, false, hashes) {
		t.Fatal("disabled hash checks must force a restart")
	}
}

func TestCaptureUsageSnapshotSkipsCorelessRuntime(t *testing.T) {
	store, err := usagesnapshot.Open(filepath.Join(t.TempDir(), "snapshots.db"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if _, err := store.Activate(nil); err != nil {
		t.Fatal(err)
	}

	client := &fakeStatsClient{}
	manager := &Manager{
		state:          state.New("test"),
		singStats:      client,
		usageSnapshots: store,
	}
	manager.CaptureUsageSnapshot(context.Background())
	if client.queryCalls != 0 {
		t.Fatalf("coreless capture queried stats %d times", client.queryCalls)
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
	runtimeState := state.New("test")
	runtimeState.SetRunningCore(state.CoreTypeSingBox)
	manager := &Manager{state: runtimeState, singStats: client}
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
	runtimeState := state.New("test")
	runtimeState.SetRunningCore(state.CoreTypeSingBox)
	manager := &Manager{state: runtimeState, singStats: client}
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
	runtimeState := state.New("test")
	runtimeState.SetRunningCore(state.CoreTypeSingBox)
	manager := &Manager{state: runtimeState, singStats: client}
	response := manager.GetInboundStats(context.Background(), GetTagStatsRequest{Tag: "edge"})
	item := response["response"].(map[string]any)
	if item["uplink"] != int64(11) || item["downlink"] != int64(22) {
		t.Fatalf("unexpected inbound stats: %#v", item)
	}
}

func TestGetSystemStatsRejectsOfflineCore(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	manager := &Manager{
		state:   state.New("test"),
		network: system.NewNetworkMonitor(logger),
	}
	if _, err := manager.GetSystemStats(context.Background()); !errors.Is(err, ErrCoreUnavailable) {
		t.Fatalf("GetSystemStats() error = %v, want ErrCoreUnavailable", err)
	}
}

func TestGetSystemStatsIncludesRunningCoreInfo(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	runtimeState := state.New("test")
	runtimeState.SetRunningCore(state.CoreTypeSingBox)
	runtimeState.SetOnlineStatus(true)
	manager := &Manager{
		state:     runtimeState,
		network:   system.NewNetworkMonitor(logger),
		singStats: &fakeStatsClient{},
	}
	response, err := manager.GetSystemStats(context.Background())
	if err != nil {
		t.Fatalf("GetSystemStats() error = %v", err)
	}
	xrayInfo := response["response"].(map[string]any)["xrayInfo"]
	stats, ok := xrayInfo.(map[string]any)
	if !ok {
		t.Fatalf("xrayInfo must be an object, got %#v", xrayInfo)
	}
	if stats["uptime"] != uint32(42) || len(stats) != 10 {
		t.Fatalf("unexpected running core stats: %#v", stats)
	}
}

func TestGetSystemStatsRejectsUnavailableCoreAPI(t *testing.T) {
	runtimeState := state.New("test")
	runtimeState.SetRunningCore(state.CoreTypeSingBox)
	runtimeState.SetOnlineStatus(true)
	manager := &Manager{
		state:     runtimeState,
		singStats: &fakeStatsClient{systemErr: errors.New("connection refused")},
	}
	if _, err := manager.GetSystemStats(context.Background()); !errors.Is(err, ErrCoreUnavailable) {
		t.Fatalf("GetSystemStats() error = %v, want ErrCoreUnavailable", err)
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
	runtimeState.SetSingBoxConfig(map[string]any{"inbounds": []any{
		map[string]any{"tag": "in-a", "type": "vless", "users": []any{}},
		map[string]any{"tag": "in-b", "type": "vless", "users": []any{}},
	}})
	runtimeState.SetRunningCore(state.CoreTypeSingBox)
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
	singBoxConfig := runtimeState.SingBoxConfig()
	inbounds := asMapSlice(singBoxConfig["inbounds"])
	firstUsers := asMapSlice(inbounds[0]["users"])
	if got, want := stringValue(firstUsers[0]["name"]), statname.UserInbound("user-a", "in-a"); got != want {
		t.Fatalf("encoded sing-box stats username = %q, want %q", got, want)
	}
	if got := runtimeState.InboundUsers("in-a")[0].UserID; got != "user-a" {
		t.Fatalf("runtime inbound user should expose real user id, got %q", got)
	}
}

func TestApplySingBoxAPIConfigEncodesUsersForStats(t *testing.T) {
	rawConfig := map[string]any{
		"inbounds": []any{
			map[string]any{
				"tag":  "in-a",
				"type": "anytls",
				"users": []any{
					map[string]any{"name": "2", "password": "password-a"},
					map[string]any{"name": statname.UserInbound("3", "in-a"), "password": "password-b"},
				},
			},
		},
		"outbounds": []any{
			map[string]any{"tag": "direct", "type": "direct"},
		},
	}

	encoded := applySingBoxAPIConfig(rawConfig, config.Config{SingBoxAPIPort: 61001, SingBoxV2RayAPIPort: 61002})
	users := asMapSlice(asMapSlice(encoded["inbounds"])[0]["users"])
	if got, want := stringValue(users[0]["name"]), statname.UserInbound("2", "in-a"); got != want {
		t.Fatalf("sing-box user name = %q, want %q", got, want)
	}
	if got, want := stringValue(users[1]["name"]), statname.UserInbound("3", "in-a"); got != want {
		t.Fatalf("pre-encoded sing-box user name = %q, want %q", got, want)
	}

	experimental := encoded["experimental"].(map[string]any)
	v2rayAPI := experimental["v2ray_api"].(map[string]any)
	stats := v2rayAPI["stats"].(map[string]any)
	statsUsers := valueStrings(stats["users"])
	if !slices.Contains(statsUsers, statname.UserInbound("2", "in-a")) {
		t.Fatalf("stats users should contain encoded user, got %#v", statsUsers)
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
