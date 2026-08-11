package usagesnapshot

import (
	"path/filepath"
	"testing"
	"time"
)

func TestDurableDeltaPullAckAndRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.db")
	store, err := Open(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	baseline := []Counter{{Kind: "outbound", Name: "direct", Direction: "uplink", Value: 100}}
	status, err := store.Activate(baseline)
	if err != nil || !status.Active || status.Generation == "" {
		t.Fatalf("activate: %#v %v", status, err)
	}
	if err := store.Capture("SING_BOX", []Counter{{Kind: "outbound", Name: "direct", Direction: "uplink", Value: 125}}, time.Unix(1, 0)); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	store, err = Open(path, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	pull, err := store.Pull(PullRequest{})
	if err != nil || len(pull.Snapshots) != 1 || pull.Snapshots[0].Counters[0].Value != 25 {
		t.Fatalf("pull: %#v %v", pull, err)
	}
	status, err = store.Ack(AckRequest{Generation: pull.Generation, ThroughSequence: 1})
	if err != nil || status.Pending != 0 || status.AckedThrough != 1 {
		t.Fatalf("ack: %#v %v", status, err)
	}
}

func TestCounterResetStartsFromNewCumulativeValue(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "stats.db"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	counter := Counter{Kind: "inbound", Name: "edge", Direction: "downlink", Value: 500}
	if _, err := store.Activate([]Counter{counter}); err != nil {
		t.Fatal(err)
	}
	counter.Value = 20
	if err := store.Capture("XRAY", []Counter{counter}, time.Now()); err != nil {
		t.Fatal(err)
	}
	pull, err := store.Pull(PullRequest{})
	if err != nil || len(pull.Snapshots) != 1 || pull.Snapshots[0].Counters[0].Value != 20 {
		t.Fatalf("reset delta: %#v %v", pull, err)
	}
}

func TestExplicitCoreResetDoesNotCompareAgainstOldBaseline(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "stats.db"), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	counter := Counter{Kind: "outbound", Name: "direct", Direction: "uplink", Value: 100}
	if _, err := store.Activate([]Counter{counter}); err != nil {
		t.Fatal(err)
	}
	counter.Value = 150
	if err := store.Capture("SING_BOX", []Counter{counter}, time.Now(), true); err != nil {
		t.Fatal(err)
	}
	pull, err := store.Pull(PullRequest{})
	if err != nil || len(pull.Snapshots) != 1 || pull.Snapshots[0].Counters[0].Value != 150 {
		t.Fatalf("explicit core reset delta: %#v %v", pull, err)
	}
}

func TestQueueLimitNeverSilentlyDrops(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "stats.db"), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	counter := Counter{Kind: "user", Name: "1", Direction: "uplink", Value: 1}
	if _, err := store.Activate(nil); err != nil {
		t.Fatal(err)
	}
	if err := store.Capture("XRAY", []Counter{counter}, time.Now()); err == nil {
		t.Fatal("expected explicit queue limit error")
	}
	status, err := store.Status()
	if err != nil || status.Pending != 0 {
		t.Fatalf("failed capture must remain atomic: %#v %v", status, err)
	}
}
