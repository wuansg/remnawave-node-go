package accessaudit

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/remnawave/remnawave-node-go/internal/statname"
	bolt "go.etcd.io/bbolt"
)

const Capability = "user_access_audit_v1"

var meta = []byte("meta")
var records = []byte("records")
var pending = []byte("pending")
var index = []byte("index")
var userIDPattern = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)
var uuidPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Target struct {
	UserID        string    `json:"userId"`
	WindowID      string    `json:"windowId"`
	EnabledAt     time.Time `json:"enabledAt"`
	RetentionDays int       `json:"retentionDays"`
}
type Config struct {
	Revision  int64     `json:"revision"`
	ExpiresAt time.Time `json:"expiresAt"`
	Targets   []Target  `json:"targets"`
}
type Record struct {
	ConnectionID    string     `json:"connectionId"`
	UserID          string     `json:"userId"`
	WindowID        string     `json:"windowId"`
	Domain          string     `json:"domain"`
	DestinationIP   string     `json:"destinationIp"`
	DestinationPort int        `json:"destinationPort"`
	Inbound         string     `json:"inbound"`
	Network         string     `json:"network"`
	Protocol        string     `json:"protocol"`
	StartedAt       time.Time  `json:"startedAt"`
	ObservedAt      time.Time  `json:"observedAt"`
	ClosedAt        *time.Time `json:"closedAt"`
	Upload          string     `json:"upload"`
	Download        string     `json:"download"`
	Partial         bool       `json:"partial"`
	Sequence        uint64     `json:"sequence"`
}
type diskRecord struct {
	Record
	LastUpload       int64 `json:"lastUpload"`
	LastDownload     int64 `json:"lastDownload"`
	BaselineUpload   int64 `json:"baselineUpload"`
	BaselineDownload int64 `json:"baselineDownload"`
	RetentionDays    int   `json:"retentionDays"`
}
type Status struct {
	Generation   string    `json:"generation"`
	Revision     int64     `json:"revision"`
	EnabledUsers int       `json:"enabledUsers"`
	Capturing    bool      `json:"capturing"`
	Pending      int       `json:"pending"`
	Dropped      uint64    `json:"dropped"`
	LastError    string    `json:"lastError"`
	ExpiresAt    time.Time `json:"expiresAt"`
}
type Batch struct {
	Generation string   `json:"generation"`
	Records    []Record `json:"records"`
	HasMore    bool     `json:"hasMore"`
}
type Store struct {
	db        *bolt.DB
	maxBytes  int64
	mu        sync.Mutex
	config    Config
	lastError string
	capturing bool
}

func Open(path string, maxBytes int64) (*Store, error) {
	if maxBytes <= 0 {
		maxBytes = 32 << 20
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	db, err := bolt.Open(path, 0600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, maxBytes: maxBytes}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{meta, records, pending, index} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		m := tx.Bucket(meta)
		if len(m.Get([]byte("generation"))) == 0 {
			var id [16]byte
			if _, err := rand.Read(id[:]); err != nil {
				return err
			}
			if err := m.Put([]byte("generation"), []byte(hex.EncodeToString(id[:]))); err != nil {
				return err
			}
		}
		if d := m.Get([]byte("config")); d != nil {
			if err := json.Unmarshal(d, &s.config); err != nil {
				return err
			}
			// A restarted Agent must renew authorization with the panel before collecting.
			s.config.ExpiresAt = time.Time{}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}
func (s *Store) Close() error { return s.db.Close() }
func Validate(c Config, now time.Time) error {
	if c.Revision < 0 || c.Revision > 9007199254740991 || len(c.Targets) > 10000 || !c.ExpiresAt.After(now) || c.ExpiresAt.After(now.Add(5*time.Minute)) {
		return errors.New("invalid audit policy lease")
	}
	seen := map[string]bool{}
	for _, t := range c.Targets {
		if !userIDPattern.MatchString(t.UserID) || !uuidPattern.MatchString(t.WindowID) || t.EnabledAt.IsZero() || t.EnabledAt.After(now.Add(time.Minute)) || t.RetentionDays < 1 || t.RetentionDays > 30 || seen[t.UserID] {
			return errors.New("invalid audit user policy")
		}
		seen[t.UserID] = true
	}
	return nil
}
func (s *Store) Configure(c Config, now time.Time) error {
	if err := Validate(c, now); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if c.Revision < s.config.Revision {
		return errors.New("stale audit policy revision")
	}
	if c.Revision == s.config.Revision && s.config.ExpiresAt != (time.Time{}) {
		a, _ := json.Marshal(s.config.Targets)
		b, _ := json.Marshal(c.Targets)
		if string(a) != string(b) {
			return errors.New("audit policy revision conflict")
		}
	}
	d, _ := json.Marshal(c)
	if err := s.db.Update(func(tx *bolt.Tx) error { return tx.Bucket(meta).Put([]byte("config"), d) }); err != nil {
		return err
	}
	s.config = c
	return nil
}
func (s *Store) Enabled(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.config.Targets) > 0 && s.config.ExpiresAt.After(now)
}
func (s *Store) Runtime(capturing bool, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.capturing = capturing
	s.lastError = ""
	if err != nil {
		s.lastError = "Audit stream interrupted; records may be incomplete"
	}
}
func (s *Store) Status() (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r := Status{Revision: s.config.Revision, EnabledUsers: len(s.config.Targets), Capturing: s.capturing && s.config.ExpiresAt.After(time.Now()), LastError: s.lastError, ExpiresAt: s.config.ExpiresAt}
	err := s.db.View(func(tx *bolt.Tx) error {
		r.Generation = string(tx.Bucket(meta).Get([]byte("generation")))
		r.Pending = tx.Bucket(pending).Stats().KeyN
		r.Dropped = number(tx.Bucket(meta).Get([]byte("dropped")))
		return nil
	})
	return r, err
}
func number(b []byte) uint64 {
	if len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}
func key(n uint64) []byte { b := make([]byte, 8); binary.BigEndian.PutUint64(b, n); return b }
func clipped(v string, n int) string {
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, v)
	if len(v) > n {
		return v[:n]
	}
	return v
}
func destination(c *Connection) (string, string, int) {
	host, port, err := net.SplitHostPort(c.Destination)
	if err != nil {
		host = c.Destination
	}
	n, _ := strconv.Atoi(port)
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(c.Domain), "."))
	ip := ""
	if net.ParseIP(host) != nil {
		ip = host
	} else if domain == "" {
		domain = host
	}
	if strings.ContainsAny(domain, "/:@?#") || strings.IndexFunc(domain, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 || len(domain) > 253 {
		domain = ""
	}
	return domain, ip, n
}
func (s *Store) Apply(events []Event, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.config.ExpiresAt.After(now) {
		return nil
	}
	selected := map[string]Target{}
	for _, t := range s.config.Targets {
		selected[t.UserID] = t
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		rb, pb, m, ib := tx.Bucket(records), tx.Bucket(pending), tx.Bucket(meta), tx.Bucket(index)
		for _, e := range events {
			var t Target
			var k []byte
			var d diskRecord
			if e.Connection != nil {
				c := e.Connection
				t = selected[statname.UserID(c.User)]
				if t.UserID == "" || c.OutboundType == "dns" || !uuidPattern.MatchString(e.ID) || c.CreatedAt <= 0 || c.CreatedAt > now.Add(time.Minute).UnixMilli() {
					continue
				}
				if c.ClosedAt > 0 && c.ClosedAt < t.EnabledAt.UnixMilli() {
					continue
				}
				k = []byte(t.WindowID + ":" + e.ID)
			} else {
				k = ib.Get([]byte(e.ID))
				if k == nil {
					continue
				}
				if err := json.Unmarshal(rb.Get(k), &d); err != nil {
					return err
				}
				t = selected[d.UserID]
				if t.WindowID != d.WindowID {
					continue
				}
			}
			previous := rb.Get(k)
			if previous != nil {
				if err := json.Unmarshal(previous, &d); err != nil {
					return err
				}
			} else {
				if e.Connection == nil {
					continue
				}
				c := e.Connection
				domain, ip, port := destination(c)
				d.Record = Record{ConnectionID: e.ID, UserID: t.UserID, WindowID: t.WindowID, Domain: domain, DestinationIP: ip, DestinationPort: port, Inbound: clipped(c.Inbound, 128), Network: clipped(c.Network, 16), Protocol: clipped(c.Protocol, 32), StartedAt: time.UnixMilli(c.CreatedAt).UTC()}
				d.Partial = d.StartedAt.Before(t.EnabledAt)
				if d.Partial {
					d.BaselineUpload = max(0, c.Upload)
					d.BaselineDownload = max(0, c.Download)
					d.StartedAt = t.EnabledAt.UTC()
				}
			}
			if e.Connection != nil {
				d.LastUpload = max(d.LastUpload, e.Connection.Upload)
				d.LastDownload = max(d.LastDownload, e.Connection.Download)
			} else if e.Type == 1 {
				if e.UploadDelta < 0 || e.DownloadDelta < 0 || e.UploadDelta > int64(^uint64(0)>>1)-d.LastUpload || e.DownloadDelta > int64(^uint64(0)>>1)-d.LastDownload {
					continue
				}
				d.LastUpload += e.UploadDelta
				d.LastDownload += e.DownloadDelta
			}
			closed := e.ClosedAt
			if e.Connection != nil && e.Connection.ClosedAt > closed {
				closed = e.Connection.ClosedAt
			}
			if closed > 0 {
				if e.Connection == nil {
					d.Partial = true
				}
				at := time.UnixMilli(closed).UTC()
				d.ClosedAt = &at
			}
			d.Upload = strconv.FormatInt(max(0, d.LastUpload-d.BaselineUpload), 10)
			d.Download = strconv.FormatInt(max(0, d.LastDownload-d.BaselineDownload), 10)
			d.ObservedAt = now.UTC()
			if d.ClosedAt != nil && d.ClosedAt.Before(now) {
				d.ObservedAt = d.ClosedAt.UTC()
			}
			// Only a short durable delivery/replay buffer is kept locally.
			// The panel owns the user's configurable 1–30 day historical retention.
			d.RetentionDays = 1
			oldSequence := d.Sequence
			d.Sequence = number(m.Get([]byte("sequence"))) + 1
			data, err := json.Marshal(d)
			if err != nil {
				return err
			}
			size := int64(number(m.Get([]byte("bytes")))) + int64(len(data)-len(previous))
			if size > s.maxBytes || previous == nil && number(m.Get([]byte("recordCount"))) >= 50000 {
				if err := m.Put([]byte("dropped"), key(number(m.Get([]byte("dropped")))+1)); err != nil {
					return err
				}
				continue
			}
			if err = pb.Delete(key(oldSequence)); err != nil {
				return err
			}
			if err = rb.Put(k, data); err != nil {
				return err
			}
			if previous == nil {
				if err = m.Put([]byte("recordCount"), key(number(m.Get([]byte("recordCount")))+1)); err != nil {
					return err
				}
			}
			if err = ib.Put([]byte(e.ID), k); err != nil {
				return err
			}
			if err = pb.Put(key(d.Sequence), k); err != nil {
				return err
			}
			if err = m.Put([]byte("sequence"), key(d.Sequence)); err != nil {
				return err
			}
			if err = m.Put([]byte("bytes"), key(uint64(size))); err != nil {
				return err
			}
		}
		return nil
	})
}
func (s *Store) Pull(limit int) (Batch, error) {
	if limit < 1 || limit > 500 {
		limit = 200
	}
	b := Batch{Records: []Record{}}
	err := s.db.View(func(tx *bolt.Tx) error {
		b.Generation = string(tx.Bucket(meta).Get([]byte("generation")))
		c := tx.Bucket(pending).Cursor()
		size := 0
		for k, v := c.First(); k != nil; k, v = c.Next() {
			data := tx.Bucket(records).Get(v)
			var d diskRecord
			if err := json.Unmarshal(data, &d); err != nil {
				return err
			}
			size += len(data)
			if len(b.Records) >= limit || size > 1<<20 {
				b.HasMore = true
				break
			}
			b.Records = append(b.Records, d.Record)
		}
		return nil
	})
	return b, err
}
func (s *Store) Ack(generation string, through uint64) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if generation != string(tx.Bucket(meta).Get([]byte("generation"))) {
			return errors.New("audit generation mismatch")
		}
		if through > number(tx.Bucket(meta).Get([]byte("sequence"))) {
			return errors.New("audit acknowledgement beyond latest sequence")
		}
		c := tx.Bucket(pending).Cursor()
		for k, _ := c.First(); k != nil && number(k) <= through; k, _ = c.Next() {
			if err := c.Delete(); err != nil {
				return err
			}
		}
		return nil
	})
}
func (s *Store) Prune(now time.Time) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		rb, pb, ib, m := tx.Bucket(records), tx.Bucket(pending), tx.Bucket(index), tx.Bucket(meta)
		c := rb.Cursor()
		size := number(m.Get([]byte("bytes")))
		for k, v := c.First(); k != nil; k, v = c.Next() {
			var d diskRecord
			if err := json.Unmarshal(v, &d); err != nil {
				return err
			}
			if d.ObservedAt.Before(now.Add(-time.Duration(d.RetentionDays) * 24 * time.Hour)) {
				size -= uint64(len(v))
				if err := pb.Delete(key(d.Sequence)); err != nil {
					return err
				}
				if string(ib.Get([]byte(d.ConnectionID))) == string(k) {
					if err := ib.Delete([]byte(d.ConnectionID)); err != nil {
						return err
					}
				}
				if err := c.Delete(); err != nil {
					return err
				}
				if err := m.Put([]byte("recordCount"), key(number(m.Get([]byte("recordCount")))-1)); err != nil {
					return err
				}
			}
		}
		return m.Put([]byte("bytes"), key(size))
	})
}
