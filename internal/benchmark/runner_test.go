package benchmark

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func fixture() Request {
	return Request{ID: "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa", Kind: "HARDWARE", Items: []string{"cpu"}, Family: "IPv4", Seconds: 1, BytesPerDirection: 1 << 20, Threads: 1}
}
func waitJob(t *testing.T, r *Runner, id, status string) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		j, ok := r.Get(id)
		if ok && j.Status == status {
			return
		}
		time.Sleep(time.Millisecond)
	}
	j, _ := r.Get(id)
	t.Fatalf("expected %s, got %+v", status, j)
}
func TestLifecycle(t *testing.T) {
	r, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	r.execute = func(ctx context.Context, _ Request, progress func(string, int), result func(Item)) {
		progress("cpu", 25)
		<-ctx.Done()
	}
	req := fixture()
	if _, err = r.Start(req); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Start(req); err != nil {
		t.Fatalf("idempotent start: %v", err)
	}
	changed := req
	changed.Seconds = 2
	if _, err = r.Start(changed); err == nil {
		t.Fatal("same ID with different request accepted")
	}
	other := req
	other.ID = "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb"
	if _, err = r.Start(other); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	j, _ := r.Get(req.ID)
	j.Request.Items[0] = "modified"
	again, _ := r.Get(req.ID)
	if again.Request.Items[0] != "cpu" {
		t.Fatal("Get exposed mutable state")
	}
	if !r.Cancel(req.ID) {
		t.Fatal("cancel failed")
	}
	waitJob(t, r, req.ID, "CANCELLED")
	restarted, err := New(r.dir)
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, restarted, req.ID, "CANCELLED")
}
func TestInterruptedAndBounds(t *testing.T) {
	dir := t.TempDir()
	req := fixture()
	data, _ := json.Marshal(Job{ID: req.ID, Request: req, Status: "RUNNING", CreatedAt: time.Now(), Results: []Item{}})
	if err := os.WriteFile(filepath.Join(dir, req.ID+".json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	r, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	waitJob(t, r, req.ID, "INTERRUPTED")
	for _, mutate := range []func(*Request){func(r *Request) { r.ID = "../../escape" }, func(r *Request) { r.Seconds = 60 }, func(r *Request) { r.BytesPerDirection = 1 << 30 }, func(r *Request) { r.Threads = 100 }, func(r *Request) { r.Items = []string{"download"} }, func(r *Request) { r.SourceIP = "x"; r.Interface = "y" }} {
		req = fixture()
		mutate(&req)
		if _, err = r.Start(req); err == nil {
			t.Fatal("invalid request accepted")
		}
	}
}
func TestEndpointSecurity(t *testing.T) {
	for _, raw := range []string{"https://user:secret@example.com/file", "https://example.com:22/file", "file:///etc/passwd"} {
		if _, err := parseURL(raw); err == nil {
			t.Fatal(raw)
		}
	}
	for _, ip := range []string{"127.0.0.1", "::ffff:127.0.0.1", "10.0.0.1", "169.254.169.254", "100.64.1.1", "2001:db8::1", "::1", "64:ff9b::a00:1", "fec0::1", "2001:2::1", "3fff::1"} {
		if publicIP(netip.MustParseAddr(ip)) {
			t.Fatal(ip)
		}
	}
	if !publicIP(netip.MustParseAddr("1.1.1.1")) {
		t.Fatal("public IP rejected")
	}
	req := fixture()
	req.SourceIP = "192.0.2.7"
	if _, err := sourceAddress(req); err == nil {
		t.Fatal("foreign source address accepted")
	}
}

type roundTripper func(*http.Request) (*http.Response, error)

func (f roundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }
func TestTransferBudgets(t *testing.T) {
	original := makeClient
	defer func() { makeClient = original }()
	var sent int64
	makeClient = func(_ context.Context, _ Request, _ string) (*http.Client, string, *net.Dialer, error) {
		return &http.Client{Transport: roundTripper(func(req *http.Request) (*http.Response, error) {
			if req.Method == "POST" {
				var err error
				sent, err = io.Copy(io.Discard, req.Body)
				if err != nil {
					t.Fatal(err)
				}
				if req.ContentLength != 1<<20 {
					t.Fatal(req.ContentLength)
				}
			}
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/octet-stream"}}, Body: io.NopCloser(strings.NewReader(strings.Repeat("x", 2<<20)))}, nil
		})}, "1.1.1.1:443", nil, nil
	}
	req := fixture()
	dl, err := transfer(context.Background(), req, "https://example.com/test", false)
	if err != nil {
		t.Fatal(err)
	}
	if dl["bytes"] != int64(1<<20) {
		t.Fatal(dl)
	}
	ul, err := transfer(context.Background(), req, "https://example.com/upload", true)
	if err != nil {
		t.Fatal(err)
	}
	if sent != 1<<20 || ul["bytes"] != sent {
		t.Fatal(ul)
	}
}

func TestPinnedEndpoint(t *testing.T) {
	original := lookupTargetIPs
	defer func() { lookupTargetIPs = original }()
	lookupTargetIPs = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("10.0.0.1")}, nil
	}
	if _, _, _, err := pinnedClient(context.Background(), fixture(), "https://example.com/test"); err == nil {
		t.Fatal("mixed private/public DNS accepted")
	}
	lookupTargetIPs = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("2606:4700:4700::1111")}, nil
	}
	if _, _, _, err := pinnedClient(context.Background(), fixture(), "https://example.com/test"); err == nil {
		t.Fatal("IPv4 silently fell back to IPv6")
	}
	lookupTargetIPs = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	client, addr, _, err := pinnedClient(context.Background(), fixture(), "https://example.com/test")
	if err != nil {
		t.Fatal(err)
	}
	if addr != "1.1.1.1:443" {
		t.Fatal(addr)
	}
	if client.Transport.(*http.Transport).Proxy != nil {
		t.Fatal("environment proxy was enabled")
	}
	if err = client.CheckRedirect(nil, nil); err == nil {
		t.Fatal("redirects accepted")
	}
	if _, err = client.Transport.(*http.Transport).DialContext(context.Background(), "tcp", "other.example:443"); err == nil {
		t.Fatal("cross-host redirect accepted")
	}
}

func TestRestartCleanupAndCorruption(t *testing.T) {
	dir := t.TempDir()
	stale := filepath.Join(dir, "disk-benchmark-stale")
	unrelated := filepath.Join(dir, "disk-benchmark-unrelated")
	otherDisk := filepath.Join(dir, "disk-unrelated")
	corrupt := filepath.Join(dir, fixture().ID+".json")
	for _, path := range []string{stale, unrelated, otherDisk} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	for path, contents := range map[string]string{filepath.Join(stale, "test.bin"): "fio", filepath.Join(unrelated, "keep.txt"): "keep", filepath.Join(otherDisk, "test.bin"): "keep", filepath.Join(dir, "bad.json"): "{broken", filepath.Join(dir, "sing-box.json"): "{\"inbounds\":[]}", corrupt: "{broken"} {
		if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
			t.Fatal(err)
		}
	}
	runner, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Fatal("fio file survived restart")
	}
	if _, err := os.Stat(filepath.Join(unrelated, "keep.txt")); err != nil {
		t.Fatal("unrelated data was removed")
	}
	for _, path := range []string{filepath.Join(dir, "bad.json"), filepath.Join(dir, "sing-box.json"), filepath.Join(otherDisk, "test.bin")} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal("unrelated file was moved or removed", path, err)
		}
	}
	if _, err := os.Stat(corrupt + ".invalid"); err != nil {
		t.Fatal("corrupt record was not quarantined")
	}
	job, err := runner.Start(fixture())
	if err != nil || job.Status != "FAILED" {
		t.Fatal("damaged task was restarted", job, err)
	}
	restarted, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	job, err = restarted.Start(fixture())
	if err != nil || job.Status != "FAILED" {
		t.Fatal("damage tombstone did not survive restart", job, err)
	}
}

func TestHardwareTools(t *testing.T) {
	if os.Getenv("BENCHMARK_HARDWARE_TEST") != "1" {
		t.Skip("opt-in hardware test in isolated container")
	}
	runner, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()
	for _, item := range []string{"cpu", "memory", "disk"} {
		request := fixture()
		if item == "disk" {
			request.Seconds = 5
		}
		result := runner.hardware(context.Background(), request, item)
		if result.Status != "COMPLETED" {
			t.Fatalf("%s: %+v", item, result)
		}
		if result.Metrics["toolVersion"] == "" {
			t.Fatal("missing tool version")
		}
		if item == "disk" {
			for _, phase := range []string{"write", "read", "randwrite", "randread"} {
				if result.Metrics[phase] == nil {
					t.Fatal("missing disk phase", phase)
				}
			}
		}
	}
	entries, err := os.ReadDir(runner.dir)
	if err != nil || len(entries) != 0 {
		t.Fatal("temporary disk file not cleaned", entries, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err = command(ctx, "sysbench", "cpu", "--time=15", "run"); err == nil {
		t.Fatal("cancelled tool was not terminated")
	}
}

func TestPressureParsing(t *testing.T) {
	if !pressureExceeded([]byte("some avg10=30.01 avg60=1.00 avg300=0.10 total=42\n"), 25) {
		t.Fatal("busy container was not detected")
	}
	if pressureExceeded([]byte("some avg10=0.01 avg60=1.00 avg300=0.10 total=42\n"), 25) {
		t.Fatal("idle container was classified as busy")
	}
	if pressureExceeded([]byte("malformed"), 25) {
		t.Fatal("malformed pressure data was accepted")
	}
}

func TestInterfaceBinding(t *testing.T) {
	original := lookupTargetIPs
	defer func() { lookupTargetIPs = original }()
	lookupTargetIPs = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("1.1.1.1")}, nil
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		request := fixture()
		request.Interface = iface.Name
		if local, e := sourceAddress(request); e != nil || local == nil {
			continue
		}
		client, _, dialer, e := pinnedClient(context.Background(), request, "https://example.com/test")
		if e != nil {
			t.Fatal(e)
		}
		defer client.CloseIdleConnections()
		if dialer.LocalAddr == nil || dialer.Control == nil {
			t.Fatal("interface selection did not bind the source IP and device")
		}
		return
	}
	t.Skip("no usable non-loopback IPv4 interface in test environment")
}
