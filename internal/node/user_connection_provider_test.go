package node

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	cfgpkg "github.com/remnawave/remnawave-node-go/internal/config"
	"github.com/remnawave/remnawave-node-go/internal/state"
)

func TestXrayUserConnectionProviderUserIPListUsesXrayAPI(t *testing.T) {
	provider := xrayUserConnectionProvider{
		runtimeState:  state.New("test"),
		apiServerAddr: "127.0.0.1:61000",
		commandPath:   "rw-core",
		runCommand: func(context.Context, string, ...string) ([]byte, error) {
			return []byte(`{"name":"user>>>2>>>online","ips":{"8.8.8.8":"1710000000","1.1.1.1":1710000300}}`), nil
		},
	}

	items, err := provider.UserIPList(context.Background(), "2")
	if err != nil {
		t.Fatalf("expected xray api user ip list to succeed: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 online IPs, got %d", len(items))
	}
	if items[0].IP != "1.1.1.1" || items[1].IP != "8.8.8.8" {
		t.Fatalf("expected ips to be sorted by last seen desc, got %#v", items)
	}
}

func TestXrayUserConnectionProviderUsersIPListUsesXrayAPI(t *testing.T) {
	calls := 0
	provider := xrayUserConnectionProvider{
		runtimeState:  state.New("test"),
		apiServerAddr: "127.0.0.1:61000",
		commandPath:   "rw-core",
		runCommand: func(_ context.Context, _ string, args ...string) ([]byte, error) {
			calls++
			switch {
			case slices.Contains(args, "statsgetallonlineusers"):
				return []byte(`{"users":["2","5"]}`), nil
			case slices.Contains(args, "-email") && args[len(args)-1] == "2":
				return []byte(`{"name":"user>>>2>>>online","ips":{"8.8.8.8":"1710000000"}}`), nil
			case slices.Contains(args, "-email") && args[len(args)-1] == "5":
				return []byte(`{"name":"user>>>5>>>online","ips":{"1.1.1.1":"1710000300"}}`), nil
			default:
				return nil, errors.New("unexpected command")
			}
		},
	}

	items, err := provider.UsersIPList(context.Background())
	if err != nil {
		t.Fatalf("expected xray api users ip list to succeed: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 online users, got %d", len(items))
	}
	if calls != 3 {
		t.Fatalf("expected 3 xray api calls, got %d", calls)
	}
	if items["2"][0].IP != "8.8.8.8" || items["5"][0].IP != "1.1.1.1" {
		t.Fatalf("unexpected online users response: %#v", items)
	}
}

func TestXrayUserConnectionProviderFallsBackWhenAPIUnavailable(t *testing.T) {
	runtimeState := state.New("test")
	runtimeState.RecordUserIP("2", "163.125.176.65", time.Unix(1710000000, 0))

	provider := xrayUserConnectionProvider{
		runtimeState:  runtimeState,
		apiServerAddr: "127.0.0.1:61000",
		commandPath:   "rw-core",
		runCommand: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("failed to dial 127.0.0.1:61000"), errors.New("exit status 1")
		},
	}

	items, err := provider.UserIPList(context.Background(), "2")
	if err != nil {
		t.Fatalf("expected xray api unavailability to fall back to runtime state: %v", err)
	}
	if len(items) != 1 || items[0].IP != "163.125.176.65" {
		t.Fatalf("expected runtime fallback ip list, got %#v", items)
	}
}

func TestXrayUserConnectionProviderReturnsEmptyWhenUserIsOffline(t *testing.T) {
	provider := xrayUserConnectionProvider{
		runtimeState:  state.New("test"),
		apiServerAddr: "127.0.0.1:61000",
		commandPath:   "rw-core",
		runCommand: func(context.Context, string, ...string) ([]byte, error) {
			return []byte("failed to get stats: rpc error: code = NotFound desc = user>>>2>>>online not found."), errors.New("exit status 1")
		},
	}

	items, err := provider.UserIPList(context.Background(), "2")
	if err != nil {
		t.Fatalf("expected offline user to return empty ip list: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("expected offline user ip list to be empty, got %#v", items)
	}
}

func TestApplyXrayAPIConfigEnablesStatsService(t *testing.T) {
	config := map[string]any{
		"inbounds": []any{
			map[string]any{"tag": "main", "protocol": "vless"},
		},
	}

	out := applyXrayAPIConfig(config, cfgpkg.Config{XtlsAPIPort: 61000}, emptyPluginState(), nil)

	api := ensureConfigMap(out["api"])
	if stringValue(api["tag"]) != xrayAPITag {
		t.Fatalf("expected xray api tag %q, got %q", xrayAPITag, stringValue(api["tag"]))
	}
	if got := valueStrings(api["services"]); !slices.Contains(got, "StatsService") {
		t.Fatalf("expected stats service to be enabled, got %#v", got)
	}

	policy := ensureConfigMap(out["policy"])
	levels := ensureConfigMap(policy["levels"])
	level0 := ensureConfigMap(levels["0"])
	if !boolValue(level0["statsUserOnline"]) || !boolValue(level0["statsUserUplink"]) || !boolValue(level0["statsUserDownlink"]) {
		t.Fatalf("expected user stats policy flags to be enabled, got %#v", level0)
	}

	system := ensureConfigMap(policy["system"])
	if !boolValue(system["statsInboundUplink"]) || !boolValue(system["statsOutboundDownlink"]) {
		t.Fatalf("expected system stats policy flags to be enabled, got %#v", system)
	}

	if len(asMapSlice(out["inbounds"])) != 2 {
		t.Fatalf("expected api inbound to be appended, got %#v", out["inbounds"])
	}
	if !hasXrayAPIRoute(asMapSlice(ensureConfigMap(out["routing"])["rules"]), xrayAPITag) {
		t.Fatalf("expected xray api route to be added, got %#v", out["routing"])
	}
}

func TestSingBoxUserConnectionProviderUsesClashAPI(t *testing.T) {
	provider := singBoxUserConnectionProvider{
		apiBaseURL: "http://sing-box.test",
		apiSecret:  "test-secret",
		httpClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if got := r.Header.Get("Authorization"); got != "Bearer test-secret" {
					t.Fatalf("expected bearer token, got %q", got)
				}
				return newHTTPResponse(http.StatusOK, `{"connections":[{"id":"a","metadata":{"sourceIP":"8.8.8.8","user":"2"}},{"id":"b","metadata":{"sourceIP":"1.1.1.1","user":"2"}},{"id":"c","metadata":{"sourceIP":"9.9.9.9","user":"5"}}]}`), nil
			}),
		},
	}

	items, err := provider.UserIPList(context.Background(), "2")
	if err != nil {
		t.Fatalf("expected sing-box user ip list to succeed: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 sing-box user IPs, got %d", len(items))
	}

	allUsers, err := provider.UsersIPList(context.Background())
	if err != nil {
		t.Fatalf("expected sing-box users ip list to succeed: %v", err)
	}
	if len(allUsers) != 2 {
		t.Fatalf("expected 2 sing-box users, got %d", len(allUsers))
	}
	if allUsers["5"][0].IP != "9.9.9.9" {
		t.Fatalf("unexpected sing-box users response: %#v", allUsers)
	}
}

func TestSingBoxUserConnectionProviderClosesMatchedConnections(t *testing.T) {
	var deleted []string
	provider := singBoxUserConnectionProvider{
		apiBaseURL: "http://sing-box.test",
		httpClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/connections":
					return newHTTPResponse(http.StatusOK, `{"connections":[{"id":"a","metadata":{"sourceIP":"8.8.8.8","user":"2"}},{"id":"b","metadata":{"sourceIP":"1.1.1.1","user":"2"}},{"id":"c","metadata":{"sourceIP":"9.9.9.9","user":"5"}}]}`), nil
				case r.Method == http.MethodDelete:
					deleted = append(deleted, r.URL.Path)
					return newHTTPResponse(http.StatusNoContent, ""), nil
				default:
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					return nil, nil
				}
			}),
		},
	}

	if err := provider.CloseUserConnections(context.Background(), "2"); err != nil {
		t.Fatalf("expected sing-box close user connections to succeed: %v", err)
	}
	if !slices.Equal(deleted, []string{"/connections/a", "/connections/b"}) {
		t.Fatalf("unexpected deleted connection ids: %#v", deleted)
	}
}

func TestApplySingBoxAPIConfigEnablesClashAPI(t *testing.T) {
	config := map[string]any{
		"inbounds": []any{
			map[string]any{"tag": "anytls", "type": "anytls"},
		},
	}

	out := applySingBoxAPIConfig(config, cfgpkg.Config{
		SingBoxAPIPort:      61001,
		SingBoxV2RayAPIPort: 61002,
		InternalRESTToken:   "test-secret",
	})

	experimental := ensureConfigMap(out["experimental"])
	clashAPI := ensureConfigMap(experimental["clash_api"])
	if stringValue(clashAPI["external_controller"]) != "127.0.0.1:61001" {
		t.Fatalf("unexpected sing-box clash api listen address: %#v", clashAPI)
	}
	if stringValue(clashAPI["secret"]) != "test-secret" {
		t.Fatalf("expected sing-box clash api secret to be set, got %#v", clashAPI)
	}
	v2rayAPI := ensureConfigMap(experimental["v2ray_api"])
	if stringValue(v2rayAPI["listen"]) != "127.0.0.1:61002" {
		t.Fatalf("unexpected sing-box v2ray api address: %#v", v2rayAPI)
	}
}

func TestApplyXrayAPIConfigBuildsTorrentBlockerRules(t *testing.T) {
	config := map[string]any{
		"inbounds":  []any{map[string]any{"tag": "main", "protocol": "vless"}},
		"outbounds": []any{},
		"routing": map[string]any{"rules": []any{
			map[string]any{"ruleTag": "watched", "outboundTag": "direct"},
		}},
	}
	plugin := emptyPluginState()
	plugin.TorrentEnabled = true
	plugin.TorrentIncludeRuleTags["watched"] = struct{}{}
	out := applyXrayAPIConfig(config, cfgpkg.Config{XtlsAPIPort: 61000, InternalSocketPath: "/run/test.sock", InternalRESTToken: "token"}, plugin, nil)

	foundTorrentRule, foundWatchedWebhook := false, false
	for _, rule := range asMapSlice(ensureConfigMap(out["routing"])["rules"]) {
		if stringValue(rule["outboundTag"]) == torrentOutboundTag {
			foundTorrentRule = slices.Contains(valueStrings(rule["protocol"]), "bittorrent") && ensureConfigMap(rule["webhook"])["url"] != nil
		}
		if stringValue(rule["ruleTag"]) == "watched" && ensureConfigMap(rule["webhook"])["url"] != nil {
			foundWatchedWebhook = true
		}
	}
	if !foundTorrentRule || !foundWatchedWebhook {
		t.Fatalf("torrent blocker rules incomplete: %#v", ensureConfigMap(out["routing"])["rules"])
	}
	foundOutbound := false
	for _, outbound := range asMapSlice(out["outbounds"]) {
		foundOutbound = foundOutbound || stringValue(outbound["tag"]) == torrentOutboundTag
	}
	if !foundOutbound {
		t.Fatalf("torrent blocker outbound missing: %#v", out["outbounds"])
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func newHTTPResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}
