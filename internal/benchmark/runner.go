package benchmark

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const Capability = "node_benchmarks_v1"

var ErrBusy = errors.New("a node benchmark is already running")

type Target struct {
	ID          string `json:"id"`
	City        string `json:"city"`
	Provider    string `json:"provider"`
	DownloadURL string `json:"downloadUrl"`
	UploadURL   string `json:"uploadUrl,omitempty"`
	PolicyURL   string `json:"policyUrl"`
}
type Request struct {
	ID                string   `json:"id"`
	Kind              string   `json:"kind"`
	Items             []string `json:"items"`
	Targets           []Target `json:"targets,omitempty"`
	Family            string   `json:"family"`
	SourceIP          string   `json:"sourceIp,omitempty"`
	Interface         string   `json:"interface,omitempty"`
	Seconds           int      `json:"seconds"`
	BytesPerDirection int64    `json:"bytesPerDirection"`
	Threads           int      `json:"threads"`
}
type Item struct {
	Name    string         `json:"name"`
	Status  string         `json:"status"`
	Message string         `json:"message,omitempty"`
	Metrics map[string]any `json:"metrics"`
}
type Job struct {
	ID         string     `json:"id"`
	Request    Request    `json:"request"`
	Status     string     `json:"status"`
	Phase      string     `json:"phase"`
	Progress   int        `json:"progress"`
	CreatedAt  time.Time  `json:"createdAt"`
	FinishedAt *time.Time `json:"finishedAt"`
	Results    []Item     `json:"results"`
	Message    string     `json:"message,omitempty"`
}
type Runner struct {
	mu      sync.Mutex
	dir     string
	jobs    map[string]*Job
	active  string
	cancel  context.CancelFunc
	execute func(context.Context, Request, func(string, int), func(Item))
}

func validID(id string) bool {
	if len(id) != 36 {
		return false
	}
	for i, c := range id {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func New(dir string) (*Runner, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	r := &Runner{dir: dir, jobs: map[string]*Job{}}
	r.execute = r.run
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json.invalid") {
			id := strings.TrimSuffix(entry.Name(), ".json.invalid")
			if validID(id) && r.jobs[id] == nil {
				r.jobs[id] = damagedJob(id, entry)
			}
			continue
		}
		// These directories contain only this runner's disposable fio file.
		// Never recurse into an arbitrary directory in the state volume.
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "disk-benchmark-") {
			path := filepath.Join(dir, entry.Name())
			files, e := os.ReadDir(path)
			if e == nil && (len(files) == 0 || len(files) == 1 && files[0].Name() == "test.bin" && files[0].Type().IsRegular()) {
				_ = os.Remove(filepath.Join(path, "test.bin"))
				_ = os.Remove(path)
			}
			continue
		}
		if strings.HasSuffix(entry.Name(), ".json.tmp") && validID(strings.TrimSuffix(entry.Name(), ".json.tmp")) {
			_ = os.Remove(filepath.Join(dir, entry.Name()))
			continue
		}
		if filepath.Ext(entry.Name()) != ".json" || !validID(strings.TrimSuffix(entry.Name(), ".json")) {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		file, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		data, readErr := io.ReadAll(io.LimitReader(file, 512*1024+1))
		_ = file.Close()
		var j Job
		if readErr != nil || len(data) > 512*1024 || json.Unmarshal(data, &j) != nil || !validID(j.ID) || entry.Name() != j.ID+".json" {
			// A damaged benchmark record must not prevent the node/core startup.
			if err = os.Rename(path, path+".invalid"); err != nil {
				return nil, err
			}
			id := strings.TrimSuffix(entry.Name(), ".json")
			r.jobs[id] = damagedJob(id, entry)
			continue
		}
		if j.Status == "RUNNING" {
			now := time.Now().UTC()
			j.Status = "INTERRUPTED"
			j.Message = "Agent restarted during test"
			j.FinishedAt = &now
		}
		r.jobs[j.ID] = &j
		if err = r.save(&j); err != nil {
			return nil, err
		}
	}
	r.prune()
	return r, nil
}
func validate(req Request) error {
	if !validID(req.ID) {
		return errors.New("invalid task ID")
	}
	if req.Kind != "HARDWARE" && req.Kind != "NETWORK" {
		return errors.New("invalid test kind")
	}
	if req.Seconds < 1 || req.Seconds > 15 || req.Threads < 1 || req.Threads > 8 || req.BytesPerDirection < 1<<20 || req.BytesPerDirection > 256<<20 {
		return errors.New("test exceeds resource limits")
	}
	if req.Family != "IPv4" && req.Family != "IPv6" {
		return errors.New("invalid address family")
	}
	if req.SourceIP != "" && req.Interface != "" {
		return errors.New("select either source IP or interface")
	}
	allowed := map[string]bool{"cpu": req.Kind == "HARDWARE", "memory": req.Kind == "HARDWARE", "disk": req.Kind == "HARDWARE", "latency": req.Kind == "NETWORK", "download": req.Kind == "NETWORK", "upload": req.Kind == "NETWORK"}
	seen := map[string]bool{}
	for _, item := range req.Items {
		if !allowed[item] || seen[item] {
			return errors.New("invalid or duplicate test item")
		}
		seen[item] = true
	}
	if len(req.Items) == 0 || len(req.Items) > 3 {
		return errors.New("select test items")
	}
	if req.Kind == "NETWORK" {
		if len(req.Targets) == 0 || len(req.Targets) > 12 {
			return errors.New("select between 1 and 12 targets")
		}
		seen = map[string]bool{}
		for _, t := range req.Targets {
			if t.ID == "" || len(t.ID) > 64 || seen[t.ID] || len(t.City) > 64 || len(t.Provider) > 128 {
				return errors.New("invalid target")
			}
			seen[t.ID] = true
			if _, err := parseURL(t.DownloadURL); err != nil {
				return err
			}
			if t.UploadURL != "" {
				if _, err := parseURL(t.UploadURL); err != nil {
					return err
				}
			}
		}
	} else if len(req.Targets) != 0 {
		return errors.New("hardware tests do not accept network targets")
	}
	return nil
}
func (r *Runner) Start(req Request) (Job, error) {
	req.Items = append([]string(nil), req.Items...)
	req.Targets = append([]Target(nil), req.Targets...)
	if err := validate(req); err != nil {
		return Job{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if existing := r.jobs[req.ID]; existing != nil {
		// An unreadable previous job remains a terminal tombstone. Retrying
		// that ID must not silently spend the traffic budget a second time.
		if existing.Request.ID == "" && existing.Status == "FAILED" {
			return clone(existing), nil
		}
		a, _ := json.Marshal(existing.Request)
		b, _ := json.Marshal(req)
		if string(a) != string(b) {
			return Job{}, errors.New("task ID already has a different request")
		}
		return clone(existing), nil
	}
	if r.active != "" {
		return Job{}, ErrBusy
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	j := &Job{ID: req.ID, Request: req, Status: "RUNNING", Phase: "starting", CreatedAt: time.Now().UTC(), Results: []Item{}}
	if err := r.save(j); err != nil {
		cancel()
		return Job{}, err
	}
	r.jobs[j.ID] = j
	r.active = j.ID
	r.cancel = cancel
	go func() {
		defer cancel()
		r.execute(ctx, req, func(phase string, progress int) {
			r.change(j.ID, func(j *Job) { j.Phase = phase; j.Progress = progress })
		}, func(item Item) { r.change(j.ID, func(j *Job) { j.Results = append(j.Results, item) }) })
		r.mu.Lock()
		defer r.mu.Unlock()
		now := time.Now().UTC()
		j.FinishedAt = &now
		if errors.Is(ctx.Err(), context.Canceled) {
			j.Status = "CANCELLED"
		} else if ctx.Err() != nil {
			j.Status = "FAILED"
			j.Message = "Task exceeded deadline"
		} else {
			j.Status = "COMPLETED"
			failed, skipped := 0, 0
			for _, item := range j.Results {
				if item.Status == "FAILED" {
					failed++
				}
				if item.Status == "SKIPPED" {
					skipped++
				}
			}
			if failed+skipped > 0 {
				j.Status = "PARTIAL"
			}
			if failed > 0 && failed == len(j.Results) {
				j.Status = "FAILED"
			}
			if len(j.Results) == 0 || skipped == len(j.Results) {
				j.Status = "PARTIAL"
				j.Message = "No test items could be executed"
			}
		}
		j.Progress = 100
		j.Phase = "finished"
		if err := r.save(j); err != nil {
			j.Status = "FAILED"
			j.Message = "Could not persist result"
		}
		r.active = ""
		r.cancel = nil
		r.prune()
	}()
	return clone(j), nil
}
func (r *Runner) change(id string, f func(*Job)) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j := r.jobs[id]
	f(j)
	if err := r.save(j); err != nil {
		j.Message = "Could not persist progress"
		if r.cancel != nil {
			r.cancel()
		}
	}
}
func (r *Runner) Get(id string) (Job, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	j, ok := r.jobs[id]
	if !ok {
		return Job{}, false
	}
	return clone(j), true
}
func (r *Runner) Cancel(id string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active != id {
		return false
	}
	r.cancel()
	return true
}
func (r *Runner) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancel != nil {
		r.cancel()
	}
}
func clone(j *Job) Job {
	data, _ := json.Marshal(j)
	var out Job
	_ = json.Unmarshal(data, &out)
	return out
}

func damagedJob(id string, entry os.DirEntry) *Job {
	now := time.Now().UTC()
	created := now
	if info, err := entry.Info(); err == nil {
		created = info.ModTime().UTC()
	}
	return &Job{ID: id, Status: "FAILED", Phase: "finished", Progress: 100, CreatedAt: created, FinishedAt: &now, Results: []Item{}, Message: "Previous benchmark record is damaged; test was not restarted"}
}
func (r *Runner) save(j *Job) error {
	data, err := json.Marshal(j)
	if err != nil {
		return err
	}
	if len(data) > 512*1024 {
		return errors.New("benchmark result exceeds limit")
	}
	path := filepath.Join(r.dir, j.ID+".json")
	file, err := os.OpenFile(path+".tmp", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err = file.Write(data); err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(path+".tmp", path); err != nil {
		return err
	}
	dir, err := os.Open(r.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (r *Runner) prune() {
	for len(r.jobs) > 100 {
		var oldest *Job
		for _, j := range r.jobs {
			if j.ID != r.active && (oldest == nil || j.CreatedAt.Before(oldest.CreatedAt)) {
				oldest = j
			}
		}
		if oldest == nil {
			return
		}
		_ = os.Remove(filepath.Join(r.dir, oldest.ID+".json"))
		_ = os.Remove(filepath.Join(r.dir, oldest.ID+".json.invalid"))
		delete(r.jobs, oldest.ID)
	}
	for id, j := range r.jobs {
		if id != r.active && time.Since(j.CreatedAt) > 90*24*time.Hour {
			_ = os.Remove(filepath.Join(r.dir, id+".json"))
			_ = os.Remove(filepath.Join(r.dir, id+".json.invalid"))
			delete(r.jobs, id)
		}
	}
}
func (r *Runner) run(ctx context.Context, req Request, progress func(string, int), result func(Item)) {
	if req.Kind == "HARDWARE" {
		for i, item := range req.Items {
			if ctx.Err() != nil {
				return
			}
			progress(item, i*100/len(req.Items))
			result(r.hardware(ctx, req, item))
		}
		return
	}
	for i, t := range req.Targets {
		if ctx.Err() != nil {
			return
		}
		progress(fmt.Sprintf("%s (%d/%d)", t.City, i+1, len(req.Targets)), i*100/len(req.Targets))
		result(networkTest(ctx, req, t))
	}
}
