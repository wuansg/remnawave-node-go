package node

import (
	"context"
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
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/remnawave/remnawave-node-go/internal/config"
	"github.com/remnawave/remnawave-node-go/internal/coreapi"
	"github.com/remnawave/remnawave-node-go/internal/statname"
	"golang.org/x/net/proxy"
	"google.golang.org/grpc/credentials/insecure"
)

// Opt-in real-core regression, also run by the image workflow. All endpoints
// and credentials are local test fixtures; no production config is touched.
func TestSnellIntegration(t *testing.T) {
	binary := os.Getenv("SING_BOX_TEST_BINARY")
	if binary == "" {
		t.Skip("set SING_BOX_TEST_BINARY to a patched sing-box executable")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		_, _ = io.WriteString(w, strings.Repeat("download", 4096))
	}))
	defer target.Close()
	port := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := l.Addr().(*net.TCPAddr).Port
		_ = l.Close()
		return p
	}
	start := func(label string, cfg map[string]any, listenPort int) func() {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.json")
		data, err := json.Marshal(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		log, err := os.Create(filepath.Join(dir, "core.log"))
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(binary, "run", "-c", path)
		if _, mihomo := cfg["proxies"]; mihomo {
			cmd = exec.Command(os.Getenv("MIHOMO_TEST_BINARY"), "-d", dir, "-f", path)
		}
		cmd.Stdout, cmd.Stderr = log, log
		if err = cmd.Start(); err != nil {
			t.Fatal(err)
		}
		var once sync.Once
		stop := func() { once.Do(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = log.Close() }) }
		t.Cleanup(stop)
		t.Cleanup(func() {
			if t.Failed() {
				output, _ := os.ReadFile(filepath.Join(dir, "core.log"))
				t.Logf("%s log: %s", label, output)
			}
		})
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
			conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(listenPort)), 50*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				return stop
			}
			time.Sleep(20 * time.Millisecond)
		}
		stop()
		output, _ := os.ReadFile(filepath.Join(dir, "core.log"))
		t.Fatalf("%s did not start: %s", label, output)
		return stop
	}
	snellPort, statsPort, clashPort := port(), port(), port()
	users := []any{
		map[string]any{"name": "18", "psk": "integration-user-one-12345"},
		map[string]any{"name": "19", "psk": "integration-user-two-12345"},
	}
	serverConfig := func(allowed []any) map[string]any {
		return applySingBoxAPIConfig(map[string]any{
			"log":       map[string]any{"level": "error"},
			"inbounds":  []any{map[string]any{"type": "snell", "tag": "snell", "listen": "127.0.0.1", "listen_port": snellPort, "version": 5, "multi_user_psk": true, "users": allowed}},
			"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		}, config.Config{SingBoxAPIPort: clashPort, SingBoxV2RayAPIPort: statsPort})
	}
	stopServer := start("server", serverConfig(users), snellPort)
	proxies := make([]*http.Client, 2)
	for i, user := range users {
		socksPort := port()
		start(fmt.Sprintf("client-%d", i), map[string]any{
			"log":       map[string]any{"level": "error"},
			"inbounds":  []any{map[string]any{"type": "socks", "listen": "127.0.0.1", "listen_port": socksPort}},
			"outbounds": []any{map[string]any{"type": "snell", "server": "127.0.0.1", "server_port": snellPort, "version": 4, "psk": user.(map[string]any)["psk"]}},
		}, socksPort)
		dialer, err := proxy.SOCKS5("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), nil, &net.Dialer{Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		transport := &http.Transport{DialContext: dialer.(proxy.ContextDialer).DialContext, DisableKeepAlives: true}
		t.Cleanup(transport.CloseIdleConnections)
		proxies[i] = &http.Client{Transport: transport, Timeout: 3 * time.Second}
	}
	request := func(client *http.Client) error {
		resp, err := client.Post(target.URL, "application/octet-stream", strings.NewReader(strings.Repeat("upload", 2048)))
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		if len(body) != 32768 {
			return fmt.Errorf("wrong response length: %d", len(body))
		}
		return nil
	}
	if os.Getenv("MIHOMO_TEST_BINARY") != "" {
		socksPort := port()
		start("mihomo", map[string]any{
			"mixed-port": socksPort, "allow-lan": false, "bind-address": "127.0.0.1",
			"mode": "rule", "log-level": "debug", "external-controller": "",
			"proxies": []any{map[string]any{"name": "snell", "type": "snell", "server": "127.0.0.1", "port": snellPort, "version": 5, "psk": "integration-user-one-12345", "udp": true}},
			"rules":   []string{"MATCH,snell"},
		}, socksPort)
		proxyURL, _ := url.Parse(fmt.Sprintf("http://127.0.0.1:%d", socksPort))
		transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
		t.Cleanup(transport.CloseIdleConnections)
		client := &http.Client{Transport: transport, Timeout: 3 * time.Second}
		// Mihomo opens its mixed listener before the routing engine is ready.
		// Probe readiness, then require repeated successes without retries.
		var readyErr error
		for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); {
			readyErr = request(client)
			if readyErr == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if readyErr != nil {
			t.Fatalf("Mihomo readiness: %v", readyErr)
		}
		for i := 0; i < 5; i++ {
			if err := request(client); err != nil {
				t.Fatalf("Mihomo compatibility: %v", err)
			}
		}
	}
	for _, client := range proxies {
		if err := request(client); err != nil {
			t.Fatal(err)
		}
	}
	stats, err := coreapi.NewSingBoxStatsClient(fmt.Sprintf("127.0.0.1:%d", statsPort), insecure.NewCredentials())
	if err != nil {
		t.Fatal(err)
	}
	defer stats.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	entries, err := stats.Query(ctx, "user>>>", false)
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int64{}
	for _, entry := range entries {
		counts[entry.Name] = entry.Value
	}
	for _, id := range []string{"18", "19"} {
		prefix := "user>>>" + statname.UserInbound(id, "snell") + ">>>traffic>>>"
		if counts[prefix+"uplink"] < 12288 || counts[prefix+"downlink"] < 32768 {
			t.Fatalf("missing separate upload/download for %s: %v", id, counts)
		}
	}
	stopServer()
	stopServer = start("revoked-server", serverConfig(users[:1]), snellPort)
	if err := request(proxies[1]); err == nil {
		t.Fatal("removed user still connects")
	}
	if err := request(proxies[0]); err != nil {
		t.Fatalf("remaining user broken: %v", err)
	}
	stopServer()
	start("empty-server", serverConfig([]any{}), snellPort)
	if err := request(proxies[0]); err == nil {
		t.Fatal("empty users permits access")
	}
}
