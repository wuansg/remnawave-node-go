package node

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/remnawave/remnawave-node-go/internal/config"
	"github.com/remnawave/remnawave-node-go/internal/coreapi"
	"github.com/remnawave/remnawave-node-go/internal/state"
	"github.com/remnawave/remnawave-node-go/internal/statname"
	"github.com/remnawave/remnawave-node-go/internal/supervisor"
	"github.com/remnawave/remnawave-node-go/internal/usagesnapshot"
)

// scriptedSnapshotStats answers user queries from a script and blocks or
// fails on demand, so capture behaviour around RPC failures can be pinned.
type scriptedSnapshotStats struct {
	fakeStatsClient
	hang      bool
	userErr   error
	userValue int64
}

func (s *scriptedSnapshotStats) Query(ctx context.Context, pattern string, _ bool) ([]coreapi.Stat, error) {
	if s.hang {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if pattern != "user>>>" {
		return nil, nil
	}
	if s.userErr != nil {
		return nil, s.userErr
	}
	return []coreapi.Stat{{Name: "user>>>" + statname.UserInbound("22", "in") + ">>>traffic>>>downlink", Value: s.userValue}}, nil
}

func newSnapshotTestManager(t *testing.T, client coreapi.StatsClient) (*Manager, *usagesnapshot.Store) {
	t.Helper()
	store, err := usagesnapshot.Open(filepath.Join(t.TempDir(), "stats.db"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	runtimeState := state.New("test")
	runtimeState.SetRunningCore(state.CoreTypeSingBox)
	return &Manager{state: runtimeState, singStats: client, usageSnapshots: store, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}, store
}

func billedUserBytes(t *testing.T, store *usagesnapshot.Store) int64 {
	t.Helper()
	batch, err := store.Pull(usagesnapshot.PullRequest{})
	if err != nil {
		t.Fatal(err)
	}
	var total int64
	for _, snapshot := range batch.Snapshots {
		for _, counter := range snapshot.Counters {
			if counter.Kind == "user" && counter.Name == "22" {
				total += counter.Value
			}
		}
	}
	return total
}

func TestCaptureUsageSnapshotReleasesLifecycleLockWhenStatsHang(t *testing.T) {
	previous := usageCaptureTimeout
	usageCaptureTimeout = 50 * time.Millisecond
	t.Cleanup(func() { usageCaptureTimeout = previous })

	manager, store := newSnapshotTestManager(t, &scriptedSnapshotStats{hang: true})
	if _, err := store.Activate(nil); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { defer close(done); manager.CaptureUsageSnapshot(context.Background()) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("capture kept coreMu while the stats RPC hung")
	}
	if !manager.coreMu.TryLock() {
		t.Fatal("coreMu is still held after the capture returned")
	}
	manager.coreMu.Unlock()
}

func TestCaptureUsageSnapshotKeepsRestartMarkerWhenCoreStatsFail(t *testing.T) {
	client := &scriptedSnapshotStats{userErr: errors.New("stats unavailable")}
	manager, store := newSnapshotTestManager(t, client)
	baseline := usagesnapshot.Counter{Kind: "user", Name: "22", Inbound: "in", Direction: "downlink", Value: 1000}
	if _, err := store.Activate([]usagesnapshot.Counter{baseline}); err != nil {
		t.Fatal(err)
	}
	manager.usageCoreRestarted = true

	manager.CaptureUsageSnapshot(context.Background())
	if !manager.usageCoreRestarted {
		t.Fatal("a failed core sample consumed the restart marker")
	}

	// After the restart the counter restarted from zero and already passed
	// the old baseline; without the marker only 1500-1000 would be billed.
	client.userErr, client.userValue = nil, 1500
	manager.CaptureUsageSnapshot(context.Background())
	if manager.usageCoreRestarted {
		t.Fatal("a complete core sample did not consume the restart marker")
	}
	if billed := billedUserBytes(t, store); billed != 1500 {
		t.Fatalf("billed %d bytes after restart, want 1500", billed)
	}
}

func TestActivateUsageSnapshotsRejectsIncompleteCoreBaseline(t *testing.T) {
	manager, store := newSnapshotTestManager(t, &scriptedSnapshotStats{userErr: errors.New("stats unavailable")})
	if _, err := manager.ActivateUsageSnapshots(context.Background()); !errors.Is(err, ErrCoreUnavailable) {
		t.Fatalf("activation error = %v, want ErrCoreUnavailable", err)
	}
	if store.Active() {
		t.Fatal("activation stored a baseline without core counters")
	}
}

func TestRestartCoreSealsPreRestartUsageAndMarksRestart(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "sing-box.json")
	lastGoodPath := filepath.Join(dir, "sing-box.last-good.json")
	initialBytes := []byte(`{"inbounds":[{"tag":"in","type":"anytls","users":[]}]}`)
	if err := os.WriteFile(configPath, initialBytes, 0o644); err != nil {
		t.Fatal(err)
	}

	client := &scriptedSnapshotStats{userValue: 1300}
	manager, store := newSnapshotTestManager(t, client)
	baseline := usagesnapshot.Counter{Kind: "user", Name: "22", Inbound: "in", Direction: "downlink", Value: 1000}
	if _, err := store.Activate([]usagesnapshot.Counter{baseline}); err != nil {
		t.Fatal(err)
	}

	fakeSupervisor := newFakeProcessSupervisor()
	fakeSupervisor.states[singBoxProcessName] = supervisor.StateRunning
	manager.cfg = config.Config{
		SingBoxConfigPath:   configPath,
		SingBoxLastGoodPath: lastGoodPath,
		SingBoxV2RayAPIPort: 61002,
	}
	manager.supervisor = fakeSupervisor
	manager.runCommand = func(context.Context, string, ...string) ([]byte, error) { return nil, nil }
	manager.healthTimeout = 100 * time.Millisecond
	manager.healthPollInterval = time.Millisecond
	manager.state.SetSingBoxConfig(map[string]any{
		"inbounds": []any{map[string]any{"tag": "in", "type": "anytls", "users": []any{}}},
	})
	manager.state.SetOnlineStatus(true)

	result := manager.AddUser(context.Background(), AddUserRequest{
		Data: []AddUserItem{{Type: "anytls", Tag: "in", Username: "22", Password: "pw"}},
	})
	if result["response"].(map[string]any)["success"] != true {
		t.Fatalf("AddUser failed: %#v", result)
	}
	// Pre-restart delta (1300 - 1000 = 300) must already be sealed, and the
	// restart marker must be set for the next post-restart sample.
	if billed := billedUserBytes(t, store); billed != 300 {
		t.Fatalf("pre-restart billed = %d, want 300", billed)
	}
	if !manager.usageCoreRestarted {
		t.Fatal("restartCurrentCore did not set usageCoreRestarted")
	}

	// Simulate post-restart counter starting at 0 and already surpassing the
	// pre-restart 1300 baseline before the next periodic capture.
	client.userValue = 1500
	manager.CaptureUsageSnapshot(context.Background())
	if billed := billedUserBytes(t, store); billed != 1800 {
		t.Fatalf("total billed across user-update restart = %d, want 1800 (300 pre-restart + 1500 post-restart)", billed)
	}
}

func TestStopSealsCoreUsageAndPreservesRestartMarkerWhileStopped(t *testing.T) {
	client := &scriptedSnapshotStats{userValue: 1250}
	manager, store := newSnapshotTestManager(t, client)
	manager.supervisor = newFakeProcessSupervisor()
	baseline := usagesnapshot.Counter{Kind: "user", Name: "22", Inbound: "in", Direction: "downlink", Value: 1000}
	if _, err := store.Activate([]usagesnapshot.Counter{baseline}); err != nil {
		t.Fatal(err)
	}

	manager.Stop(context.Background())
	if billed := billedUserBytes(t, store); billed != 250 {
		t.Fatalf("billed on Stop = %d, want 250", billed)
	}
	if !manager.usageCoreRestarted {
		t.Fatal("Stop did not set usageCoreRestarted")
	}

	// Sampling while the core is stopped must not consume usageCoreRestarted.
	manager.CaptureUsageSnapshot(context.Background())
	if !manager.usageCoreRestarted {
		t.Fatal("stopped-core capture consumed usageCoreRestarted")
	}
}
