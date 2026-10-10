package accessaudit

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
func TestNativeSingBoxStreamIntegration(t *testing.T) {
	binary := os.Getenv("SING_BOX_TEST_BINARY")
	if binary == "" {
		t.Skip("set SING_BOX_TEST_BINARY to test the actual pinned sing-box core")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		w.Write([]byte(strings.Repeat("audit-download-", 100)))
	}))
	defer target.Close()
	proxyPort, apiPort, clashPort := freePort(t), freePort(t), freePort(t)
	config := map[string]any{
		"log":          map[string]any{"disabled": true},
		"inbounds":     []any{map[string]any{"type": "mixed", "tag": "fixture", "listen": "127.0.0.1", "listen_port": proxyPort, "users": []any{map[string]any{"username": "1", "password": "fixture-password"}, map[string]any{"username": "2", "password": "fixture-password"}}}},
		"outbounds":    []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route":        map[string]any{"rules": []any{map[string]any{"action": "sniff", "sniffer": []any{"tls", "http"}}}, "final": "direct"},
		"experimental": map[string]any{"clash_api": map[string]any{"external_controller": fmt.Sprintf("127.0.0.1:%d", clashPort), "secret": "fixture-secret"}},
		"services":     []any{map[string]any{"type": "api", "tag": "audit-fixture", "listen": "127.0.0.1", "listen_port": apiPort, "secret": "fixture-secret"}},
	}
	data, _ := json.Marshal(config)
	path := filepath.Join(t.TempDir(), "sing-box.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, binary, "run", "-c", path)
	if output, err := exec.CommandContext(ctx, binary, "check", "-c", path).CombinedOutput(); err != nil {
		t.Fatalf("fixture config rejected: %s", output)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { cancel(); cmd.Wait() }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		l, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", apiPort), 100*time.Millisecond)
		if err == nil {
			l.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native API did not start")
		}
		time.Sleep(50 * time.Millisecond)
	}
	s, now, c := openFixture(t, 0)
	if err := s.Configure(c, now); err != nil {
		t.Fatal(err)
	}
	collector := Start(s, fmt.Sprintf("127.0.0.1:%d", apiPort), "fixture-secret")
	defer collector.Close()
	deadline = time.Now().Add(5 * time.Second)
	for {
		status, _ := s.Status()
		if status.Capturing {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native stream unavailable")
		}
		time.Sleep(50 * time.Millisecond)
	}
	for _, user := range []string{"1", "2"} {
		p, _ := url.Parse(fmt.Sprintf("http://%s:fixture-password@127.0.0.1:%d", user, proxyPort))
		transport := &http.Transport{Proxy: http.ProxyURL(p), TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: "audit-fixture.example"}, DisableKeepAlives: true}
		client := &http.Client{Transport: transport, Timeout: 4 * time.Second}
		req, _ := http.NewRequestWithContext(ctx, "POST", target.URL, strings.NewReader("audit-upload-fixture"))
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		transport.CloseIdleConnections()
	}
	deadline = time.Now().Add(5 * time.Second)
	for {
		records := batch(t, s).Records
		found := false
		for _, r := range records {
			if r.UserID != "1" {
				t.Fatal("unselected user was persisted")
			}
			if r.Domain == "audit-fixture.example" && r.ClosedAt != nil && r.Upload != "0" && r.Download != "0" {
				found = true
			}
		}
		if found {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("missing domain/final traffic from actual core: %+v", records)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Invalid authentication must never expose the native stream.
	authCtx, stop := context.WithTimeout(context.Background(), time.Second)
	defer stop()
	if err := Subscribe(authCtx, fmt.Sprintf("127.0.0.1:%d", apiPort), "wrong-secret", func([]Event) error { return nil }); err == nil {
		t.Fatal("native API accepted invalid credentials")
	}
}
