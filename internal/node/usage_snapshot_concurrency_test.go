package node

import (
	"context"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/remnawave/remnawave-node-go/internal/coreapi"
	"github.com/remnawave/remnawave-node-go/internal/state"
	"github.com/remnawave/remnawave-node-go/internal/statname"
	"github.com/remnawave/remnawave-node-go/internal/usagesnapshot"
)

// Pause the first sample after reading its user counter but before committing
// its baseline. Without lifecycle serialization, a second capture commits 110
// first, then the older 100 is mistaken for a reset and billed in full.
type orderedSnapshotStats struct {
	fakeStatsClient
	userReads atomic.Int64
	paused    chan struct{}
	release   chan struct{}
	second    chan struct{}
	pauseOnce sync.Once
}

func (s *orderedSnapshotStats) Query(ctx context.Context, pattern string, reset bool) ([]coreapi.Stat, error) {
	if reset {
		panic("snapshot capture must not reset core counters")
	}
	switch pattern {
	case "user>>>":
		read := s.userReads.Add(1)
		value := int64(100)
		if read > 1 {
			value = 110
			if read == 2 {
				close(s.second)
			}
		}
		return []coreapi.Stat{{Name: "user>>>" + statname.UserInbound("22", "in") + ">>>traffic>>>downlink", Value: value}}, nil
	case "inbound>>>":
		if s.userReads.Load() == 1 {
			s.pauseOnce.Do(func() {
				close(s.paused)
				select {
				case <-s.release:
				case <-ctx.Done():
				}
			})
		}
	}
	return nil, nil
}

func TestUsageSnapshotCaptureSerializesSamplingAndBaselineCommit(t *testing.T) {
	for _, sealed := range []bool{false, true} {
		name := "periodic-captures"
		if sealed {
			name = "periodic-versus-forwarding-seal"
		}
		t.Run(name, func(t *testing.T) {
			store, err := usagesnapshot.Open(filepath.Join(t.TempDir(), "stats.db"), 1<<20)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			baseline := usagesnapshot.Counter{Kind: "user", Name: "22", Inbound: "in", Direction: "downlink", Value: 90}
			if _, err = store.Activate([]usagesnapshot.Counter{baseline}); err != nil {
				t.Fatal(err)
			}
			client := &orderedSnapshotStats{paused: make(chan struct{}), release: make(chan struct{}), second: make(chan struct{})}
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(client.release) }) }
			defer release()
			runtimeState := state.New("test")
			runtimeState.SetRunningCore(state.CoreTypeSingBox)
			manager := &Manager{state: runtimeState, singStats: client, usageSnapshots: store, logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			firstDone, secondDone := make(chan struct{}), make(chan error, 1)
			go func() { defer close(firstDone); manager.CaptureUsageSnapshot(ctx) }()
			select {
			case <-client.paused:
			case <-ctx.Done():
				t.Fatal("first sample did not reach the controlled pause")
			}
			secondStarted := make(chan struct{})
			go func() {
				close(secondStarted)
				if sealed {
					// ForwardingSync and RefreshForwardingDNS already hold coreMu.
					manager.coreMu.Lock()
					defer manager.coreMu.Unlock()
					secondDone <- manager.captureUsageSnapshot(ctx)
					return
				}
				manager.CaptureUsageSnapshot(ctx)
				secondDone <- nil
			}()
			<-secondStarted
			concurrentRead := false
			select {
			case <-client.second:
				concurrentRead = true
				// Force the newer sample to commit first in the broken version.
				select {
				case err = <-secondDone:
					secondDone <- err
				case <-ctx.Done():
					t.Fatal("overlapping sample did not finish")
				}
			case <-time.After(100 * time.Millisecond):
			}
			release()
			select {
			case <-firstDone:
			case <-ctx.Done():
				t.Fatal("first capture did not finish")
			}
			select {
			case err = <-secondDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("second capture did not finish")
			}
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
			if concurrentRead || total != 20 {
				t.Fatalf("overlapping sample=%v, billed=%d; want serialized samples and 110-90=20 bytes", concurrentRead, total)
			}
		})
	}
}

func TestUsageSnapshotActivationWaitsForLifecycleLock(t *testing.T) {
	store, err := usagesnapshot.Open(filepath.Join(t.TempDir(), "stats.db"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	client := &orderedSnapshotStats{paused: make(chan struct{}), release: make(chan struct{}), second: make(chan struct{})}
	close(client.release)
	runtimeState := state.New("test")
	runtimeState.SetRunningCore(state.CoreTypeSingBox)
	manager := &Manager{state: runtimeState, singStats: client, usageSnapshots: store}
	manager.coreMu.Lock()
	done := make(chan error, 1)
	go func() { _, activateErr := manager.ActivateUsageSnapshots(context.Background()); done <- activateErr }()
	time.Sleep(50 * time.Millisecond)
	readsWhileLocked := client.userReads.Load()
	manager.coreMu.Unlock()
	select {
	case err = <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("activation deadlocked")
	}
	if readsWhileLocked != 0 || !store.Active() {
		t.Fatalf("activation sampled during lifecycle mutation: reads=%d active=%v", readsWhileLocked, store.Active())
	}
}
