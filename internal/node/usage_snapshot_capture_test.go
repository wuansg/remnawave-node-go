package node

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/remnawave/remnawave-node-go/internal/coreapi"
	"github.com/remnawave/remnawave-node-go/internal/state"
	"github.com/remnawave/remnawave-node-go/internal/statname"
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
