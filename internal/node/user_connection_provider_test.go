package node

import (
	"context"
	"errors"
	"slices"
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

	out := applyXrayAPIConfig(config, cfgpkg.Config{XtlsAPIPort: 61000}, emptyPluginState())

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
