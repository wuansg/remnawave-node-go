package accessaudit

import (
	"encoding/json"
	"fmt"
	"github.com/remnawave/remnawave-node-go/internal/statname"
	"path/filepath"
	"testing"
	"time"
)

const selectedID = "00000000-0000-4000-8000-000000000001"
const otherID = "00000000-0000-4000-8000-000000000002"
const windowID = "10000000-0000-4000-8000-000000000001"

func openFixture(t *testing.T, maxBytes int64) (*Store, time.Time, Config) {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "audit.db"), maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	now := time.Now().UTC().Truncate(time.Millisecond)
	return s, now, Config{Revision: 1, ExpiresAt: now.Add(2 * time.Minute), Targets: []Target{{UserID: "1", WindowID: windowID, EnabledAt: now, RetentionDays: 7}}}
}
func event(id, user string, created time.Time, up, down int64) Event {
	return Event{ID: id, Connection: &Connection{ID: id, User: statname.UserInbound(user, "inbound"), Domain: "Example.COM.", Destination: "203.0.113.9:443", Inbound: "inbound", Network: "tcp", Protocol: "tls", CreatedAt: created.UnixMilli(), Upload: up, Download: down}}
}
func apply(t *testing.T, s *Store, now time.Time, e ...Event) {
	t.Helper()
	if err := s.Apply(e, now); err != nil {
		t.Fatal(err)
	}
}
func batch(t *testing.T, s *Store) Batch {
	t.Helper()
	b, err := s.Pull(500)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func TestOnlySelectedUsersAndClosedCounters(t *testing.T) {
	s, now, c := openFixture(t, 0)
	a := event(selectedID, "1", now, 100, 1000)
	b := event(otherID, "2", now, 999, 999)
	apply(t, s, now, a, b)
	if len(batch(t, s).Records) != 0 {
		t.Fatal("default must be off")
	}
	if err := s.Configure(c, now); err != nil {
		t.Fatal(err)
	}
	apply(t, s, now, a, b)
	got := batch(t, s)
	if len(got.Records) != 1 || got.Records[0].UserID != "1" || got.Records[0].Domain != "example.com" {
		t.Fatalf("unexpected selected records: %+v", got)
	}
	apply(t, s, now.Add(time.Second), Event{Type: 1, ID: selectedID, UploadDelta: 50, DownloadDelta: 500})
	closed := event(selectedID, "1", now, 175, 2000)
	closed.Type = 2
	closed.ClosedAt = now.Add(2 * time.Second).UnixMilli()
	closed.Connection.ClosedAt = closed.ClosedAt
	apply(t, s, now.Add(2*time.Second), closed)
	got = batch(t, s)
	if got.Records[0].Upload != "175" || got.Records[0].Download != "2000" || got.Records[0].ClosedAt == nil {
		t.Fatalf("final totals wrong: %+v", got.Records[0])
	}
	apply(t, s, now.Add(3*time.Second), closed)
	again := batch(t, s)
	if again.Records[0].Upload != "175" {
		t.Fatal("replay double counted")
	}
	if !again.Records[0].ObservedAt.Equal(now.Add(2 * time.Second)) {
		t.Fatal("Closed snapshot replay moved the visit time forward")
	}
	oldSeq := again.Records[0].Sequence
	apply(t, s, now.Add(4*time.Second), closed)
	if err := s.Ack(got.Generation, oldSeq); err != nil {
		t.Fatal(err)
	}
	if len(batch(t, s).Records) != 1 {
		t.Fatal("ACK deleted an update newer than the pull")
	}
	latest := batch(t, s)
	if err := s.Ack(latest.Generation, latest.Records[0].Sequence); err != nil {
		t.Fatal(err)
	}
	if len(batch(t, s).Records) != 0 {
		t.Fatal("ACK failed")
	}
	if err := s.Ack("bad-generation", 0); err == nil {
		t.Fatal("generation mismatch accepted")
	}
	if err := s.Ack(latest.Generation, 999999); err == nil {
		t.Fatal("future ACK accepted")
	}
}
func TestEnableBoundaryDisableLeaseAndRestart(t *testing.T) {
	s, now, c := openFixture(t, 0)
	if err := s.Configure(c, now); err != nil {
		t.Fatal(err)
	}
	old := event(selectedID, "1", now.Add(-time.Hour), 100, 1000)
	apply(t, s, now, old)
	apply(t, s, now.Add(time.Second), Event{Type: 1, ID: selectedID, UploadDelta: 50, DownloadDelta: 500})
	got := batch(t, s).Records[0]
	if !got.Partial || got.Upload != "50" || got.Download != "500" || !got.StartedAt.Equal(now) {
		t.Fatalf("pre-enable bytes included: %+v", got)
	}
	// Reconnect snapshots contain absolute counters; then subsequent deltas resume.
	old.Connection.Upload = 175
	old.Connection.Download = 1700
	apply(t, s, now.Add(2*time.Second), old)
	apply(t, s, now.Add(3*time.Second), Event{Type: 1, ID: selectedID, UploadDelta: 25, DownloadDelta: 300})
	got = batch(t, s).Records[0]
	if got.Upload != "100" || got.Download != "1000" {
		t.Fatalf("reconnect counters wrong: %+v", got)
	}
	c.Revision++
	c.Targets = []Target{}
	if err := s.Configure(c, now); err != nil {
		t.Fatal(err)
	}
	seq := got.Sequence
	apply(t, s, now.Add(4*time.Second), event(selectedID, "1", now, 99999, 99999))
	if batch(t, s).Records[0].Sequence != seq {
		t.Fatal("disabled user was still recorded")
	}
	if err := s.Configure(Config{Revision: 1, ExpiresAt: now.Add(time.Minute)}, now); err == nil {
		t.Fatal("stale policy accepted")
	}
	c.Revision++
	c.Targets = []Target{{UserID: "1", WindowID: windowID, EnabledAt: now, RetentionDays: 7}}
	if err := s.Configure(c, now); err != nil {
		t.Fatal(err)
	}
	apply(t, s, now.Add(3*time.Minute), event(selectedID, "1", now, 99999, 99999))
	if batch(t, s).Records[0].Sequence != seq || s.Enabled(now.Add(3*time.Minute)) {
		t.Fatal("expired policy did not fail closed")
	}
	path := s.db.Path()
	before := batch(t, s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	after := batch(t, reopened)
	if reopened.Enabled(now) {
		t.Fatal("restart must require a fresh panel lease")
	}
	if before.Generation != after.Generation || after.Records[0].Upload != "100" {
		t.Fatal("restart lost durable state")
	}
}
func TestNoHistoricalClosedRecordsAndLimits(t *testing.T) {
	s, now, c := openFixture(t, 1800)
	if err := s.Configure(c, now); err != nil {
		t.Fatal(err)
	}
	old := event(selectedID, "1", now.Add(-time.Hour), 20, 100)
	old.Connection.ClosedAt = now.Add(-time.Minute).UnixMilli()
	apply(t, s, now, old)
	if len(batch(t, s).Records) != 0 {
		t.Fatal("historical closed record retained")
	}
	for i := 1; i <= 20; i++ {
		e := event(fmt.Sprintf("00000000-0000-4000-8000-%012d", i), "1", now, 1, 10)
		apply(t, s, now, e)
	}
	status, err := s.Status()
	if err != nil {
		t.Fatal(err)
	}
	if status.Dropped == 0 {
		t.Fatal("queue limit not enforced")
	}
	if err := s.Prune(now.Add(25 * time.Hour)); err != nil {
		t.Fatal(err)
	}
	if len(batch(t, s).Records) != 0 {
		t.Fatal("retention did not prune")
	}
	// Freed logical capacity remains usable even though Bolt reuses old pages.
	c.ExpiresAt = now.Add(time.Minute)
	apply(t, s, now, event(otherID, "1", now, 1, 10))
	if len(batch(t, s).Records) != 1 {
		t.Fatal("pruned capacity was not reusable")
	}
	data, _ := json.Marshal(batch(t, s))
	if string(data) == "" {
		t.Fatal("serialization")
	}
}
func TestPolicyValidation(t *testing.T) {
	s, now, c := openFixture(t, 0)
	_ = s
	for _, bad := range []Config{{Revision: -1, ExpiresAt: c.ExpiresAt}, {Revision: 1, ExpiresAt: now.Add(time.Hour)}, {Revision: 1, ExpiresAt: c.ExpiresAt, Targets: append(c.Targets, c.Targets...)}} {
		if Validate(bad, now) == nil {
			t.Fatal("invalid policy accepted")
		}
	}
}
