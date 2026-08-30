package usagesnapshot

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

const Capability = "usage_snapshot_v1"

var (
	metaBucket      = []byte("meta")
	baselineBucket  = []byte("baseline")
	snapshotsBucket = []byte("snapshots")
	activeKey       = []byte("active")
	generationKey   = []byte("generation")
	nextSequenceKey = []byte("next_sequence")
	ackedKey        = []byte("acked_through")
	lastCapturedKey = []byte("last_captured_at")
	ErrNotActive    = errors.New("usage snapshot mode is not active")
)

type Counter struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Inbound   string `json:"inbound,omitempty"`
	Direction string `json:"direction"`
	Value     int64  `json:"value"`
}

type Snapshot struct {
	Generation string    `json:"generation"`
	Sequence   uint64    `json:"sequence"`
	CapturedAt time.Time `json:"capturedAt"`
	Core       string    `json:"core"`
	Counters   []Counter `json:"counters"`
}

type PullRequest struct {
	AfterSequence uint64 `json:"afterSequence"`
	Limit         int    `json:"limit"`
	MaxBytes      int    `json:"maxBytes"`
}

type PullResponse struct {
	Generation string     `json:"generation"`
	Snapshots  []Snapshot `json:"snapshots"`
	HasMore    bool       `json:"hasMore"`
}

type AckRequest struct {
	Generation      string `json:"generation"`
	ThroughSequence uint64 `json:"throughSequence"`
}

type Status struct {
	Active         bool   `json:"active"`
	Capturing      bool   `json:"capturing"`
	Generation     string `json:"generation"`
	OldestSequence uint64 `json:"oldestSequence"`
	LatestSequence uint64 `json:"latestSequence"`
	AckedThrough   uint64 `json:"ackedThrough"`
	Pending        int    `json:"pending"`
	Bytes          int64  `json:"bytes"`
	LastCapturedAt string `json:"lastCapturedAt,omitempty"`
}

type Store struct {
	db       *bolt.DB
	maxBytes int64
}

func Open(path string, maxBytes int64) (*Store, error) {
	if maxBytes <= 0 {
		maxBytes = 256 << 20
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create snapshot directory: %w", err)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: 2 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("open snapshot database: %w", err)
	}
	s := &Store{db: db, maxBytes: maxBytes}
	if err := db.Update(func(tx *bolt.Tx) error {
		for _, name := range [][]byte{metaBucket, baselineBucket, snapshotsBucket} {
			if _, err := tx.CreateBucketIfNotExists(name); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) Active() bool {
	active := false
	_ = s.db.View(func(tx *bolt.Tx) error { active = string(tx.Bucket(metaBucket).Get(activeKey)) == "1"; return nil })
	return active
}

func (s *Store) Activate(counters []Counter) (Status, error) {
	err := s.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket(metaBucket)
		if string(meta.Get(activeKey)) == "1" {
			return nil
		}
		generation, err := randomID()
		if err != nil {
			return err
		}
		if err := meta.Put(activeKey, []byte("1")); err != nil {
			return err
		}
		if err := meta.Put(generationKey, []byte(generation)); err != nil {
			return err
		}
		if err := putUint64(meta, nextSequenceKey, 1); err != nil {
			return err
		}
		if err := putUint64(meta, ackedKey, 0); err != nil {
			return err
		}
		if err := meta.Delete(lastCapturedKey); err != nil {
			return err
		}
		if err := clearBucket(tx.Bucket(baselineBucket)); err != nil {
			return err
		}
		if err := clearBucket(tx.Bucket(snapshotsBucket)); err != nil {
			return err
		}
		return storeBaseline(tx.Bucket(baselineBucket), counters)
	})
	if err != nil {
		return Status{}, err
	}
	return s.Status()
}

func (s *Store) Capture(core string, counters []Counter, capturedAt time.Time, coreReset ...bool) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket(metaBucket)
		if string(meta.Get(activeKey)) != "1" {
			return ErrNotActive
		}
		baseline := tx.Bucket(baselineBucket)
		reset := len(coreReset) > 0 && coreReset[0]
		deltas := make([]Counter, 0, len(counters))
		for _, counter := range counters {
			key, current := counterKey(counter), counter.Value
			previous := decodeInt64(baseline.Get(key))
			delta := current - previous
			if reset || delta < 0 {
				delta = current
			}
			if delta > 0 {
				counter.Value = delta
				deltas = append(deltas, counter)
			}
			if err := baseline.Put(key, encodeInt64(current)); err != nil {
				return err
			}
		}
		if len(deltas) == 0 {
			return nil
		}
		sequence := readUint64(meta.Get(nextSequenceKey))
		snapshot := Snapshot{Generation: string(meta.Get(generationKey)), Sequence: sequence, CapturedAt: capturedAt.UTC(), Core: core, Counters: deltas}
		payload, err := json.Marshal(snapshot)
		if err != nil {
			return err
		}
		if int64(len(payload))+snapshotBytes(tx.Bucket(snapshotsBucket)) > s.maxBytes {
			return fmt.Errorf("snapshot queue safety limit (%d bytes) exceeded", s.maxBytes)
		}
		if err := tx.Bucket(snapshotsBucket).Put(sequenceKey(sequence), payload); err != nil {
			return err
		}
		if err := putUint64(meta, nextSequenceKey, sequence+1); err != nil {
			return err
		}
		return meta.Put(lastCapturedKey, []byte(capturedAt.UTC().Format(time.RFC3339Nano)))
	})
}

func (s *Store) Pull(request PullRequest) (PullResponse, error) {
	if request.Limit <= 0 || request.Limit > 500 {
		request.Limit = 500
	}
	if request.MaxBytes <= 0 || request.MaxBytes > 4<<20 {
		request.MaxBytes = 4 << 20
	}
	response := PullResponse{Snapshots: []Snapshot{}}
	err := s.db.View(func(tx *bolt.Tx) error {
		meta := tx.Bucket(metaBucket)
		if string(meta.Get(activeKey)) != "1" {
			return ErrNotActive
		}
		response.Generation = string(meta.Get(generationKey))
		cursor, used := tx.Bucket(snapshotsBucket).Cursor(), 0
		for key, value := cursor.Seek(sequenceKey(request.AfterSequence + 1)); key != nil; key, value = cursor.Next() {
			if len(response.Snapshots) >= request.Limit || used+len(value) > request.MaxBytes {
				response.HasMore = true
				break
			}
			var snapshot Snapshot
			if err := json.Unmarshal(value, &snapshot); err != nil {
				return err
			}
			response.Snapshots = append(response.Snapshots, snapshot)
			used += len(value)
		}
		return nil
	})
	return response, err
}

func (s *Store) Ack(request AckRequest) (Status, error) {
	err := s.db.Update(func(tx *bolt.Tx) error {
		meta := tx.Bucket(metaBucket)
		if request.Generation == "" || request.Generation != string(meta.Get(generationKey)) {
			return errors.New("snapshot generation mismatch")
		}
		latest := readUint64(meta.Get(nextSequenceKey))
		if latest > 0 {
			latest--
		}
		if request.ThroughSequence > latest {
			return errors.New("ack is ahead of latest snapshot")
		}
		current := readUint64(meta.Get(ackedKey))
		if request.ThroughSequence <= current {
			return nil
		}
		cursor := tx.Bucket(snapshotsBucket).Cursor()
		for key, _ := cursor.First(); key != nil && binary.BigEndian.Uint64(key) <= request.ThroughSequence; key, _ = cursor.Next() {
			if err := cursor.Delete(); err != nil {
				return err
			}
		}
		return putUint64(meta, ackedKey, request.ThroughSequence)
	})
	if err != nil {
		return Status{}, err
	}
	return s.Status()
}

func (s *Store) Status() (Status, error) {
	var status Status
	err := s.db.View(func(tx *bolt.Tx) error {
		meta, snapshots := tx.Bucket(metaBucket), tx.Bucket(snapshotsBucket)
		status.Active = string(meta.Get(activeKey)) == "1"
		status.Generation = string(meta.Get(generationKey))
		status.LatestSequence = readUint64(meta.Get(nextSequenceKey))
		if status.LatestSequence > 0 {
			status.LatestSequence--
		}
		status.AckedThrough = readUint64(meta.Get(ackedKey))
		status.Bytes = snapshotBytes(snapshots)
		status.LastCapturedAt = string(meta.Get(lastCapturedKey))
		cursor := snapshots.Cursor()
		first, _ := cursor.First()
		if first != nil {
			status.OldestSequence = binary.BigEndian.Uint64(first)
		}
		for key, _ := cursor.First(); key != nil; key, _ = cursor.Next() {
			status.Pending++
		}
		return nil
	})
	return status, err
}

func counterKey(c Counter) []byte {
	return []byte(c.Kind + "\x00" + c.Name + "\x00" + c.Inbound + "\x00" + c.Direction)
}
func encodeInt64(v int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return b
}
func decodeInt64(b []byte) int64 {
	if len(b) != 8 {
		return 0
	}
	return int64(binary.BigEndian.Uint64(b))
}
func sequenceKey(v uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, v); return b }
func readUint64(b []byte) uint64 {
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func putUint64(bucket *bolt.Bucket, key []byte, v uint64) error {
	return bucket.Put(key, sequenceKey(v))
}
func snapshotBytes(bucket *bolt.Bucket) int64 {
	var total int64
	_ = bucket.ForEach(func(_, v []byte) error { total += int64(len(v)); return nil })
	return total
}
func clearBucket(bucket *bolt.Bucket) error {
	cursor := bucket.Cursor()
	for key, _ := cursor.First(); key != nil; key, _ = cursor.Next() {
		if err := cursor.Delete(); err != nil {
			return err
		}
	}
	return nil
}
func storeBaseline(bucket *bolt.Bucket, counters []Counter) error {
	for _, c := range counters {
		if err := bucket.Put(counterKey(c), encodeInt64(c.Value)); err != nil {
			return err
		}
	}
	return nil
}
func randomID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
