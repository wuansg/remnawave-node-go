package forwarding

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestExtractSingBoxListeners(t *testing.T) {
	config := map[string]any{"inbounds": []any{
		map[string]any{"type": "anytls", "tag": "anytls", "listen": "0.0.0.0", "listen_port": float64(443)},
		map[string]any{"type": "hysteria2", "tag": "hy2", "listen_port": float64(8443)},
		map[string]any{"type": "mixed", "tag": "local", "listen": "127.0.0.1", "listen_port": float64(1080)},
	}}
	listeners := ExtractCoreListeners("SING_BOX", config)
	if len(listeners) != 2 {
		t.Fatalf("expected 2 listeners, got %#v", listeners)
	}
	if listeners[0].Protocol != ProtocolTCP || listeners[0].Port != 443 {
		t.Fatalf("unexpected anytls listener: %#v", listeners[0])
	}
	if listeners[1].Protocol != ProtocolUDP || listeners[1].Port != 8443 {
		t.Fatalf("unexpected hysteria listener: %#v", listeners[1])
	}
}

func TestExtractXrayListeners(t *testing.T) {
	config := map[string]any{"inbounds": []any{
		map[string]any{"protocol": "vless", "tag": "grpc", "port": float64(443), "streamSettings": map[string]any{"network": "grpc"}},
		map[string]any{"protocol": "vless", "tag": "quic", "port": float64(8443), "streamSettings": map[string]any{"network": "quic"}},
		map[string]any{"protocol": "shadowsocks", "tag": "ss", "port": float64(9000), "settings": map[string]any{"network": "tcp,udp"}},
	}}
	listeners := ExtractCoreListeners("XRAY", config)
	if len(listeners) != 4 {
		t.Fatalf("expected 4 listeners, got %#v", listeners)
	}
	if listeners[0].Protocol != ProtocolTCP || listeners[1].Protocol != ProtocolUDP {
		t.Fatalf("unexpected transport inference: %#v", listeners)
	}
}

func TestValidateRejectsProtocolOverlap(t *testing.T) {
	service := New(t.TempDir()+"/forwarding.json", 2222, nil)
	cfg := Config{Enabled: true, ListenInterface: "auto", Rules: []Rule{
		{ID: "one", Name: "one", Enabled: true, Protocol: ProtocolTCPUDP, ListenPort: 55331, TargetAddress: "198.51.100.10", TargetPort: 443},
		{ID: "two", Name: "two", Enabled: true, Protocol: ProtocolUDP, ListenPort: 55331, TargetAddress: "198.51.100.11", TargetPort: 443},
	}}
	err := service.Validate(context.Background(), cfg, nil)
	if !IsConflict(err) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestValidateCoreConfigRejectsAppliedForwardingPort(t *testing.T) {
	service := New(t.TempDir()+"/forwarding.json", 2222, nil)
	service.applied = Config{Enabled: true, Rules: []Rule{{ID: "one", Name: "one", Enabled: true, Protocol: ProtocolTCP, ListenPort: 443, TargetAddress: "198.51.100.10", TargetPort: 443}}}
	err := service.ValidateCoreConfig("SING_BOX", map[string]any{"inbounds": []any{map[string]any{"type": "anytls", "tag": "public", "listen_port": float64(443)}}})
	if !IsConflict(err) {
		t.Fatalf("expected conflict, got %v", err)
	}
}

func TestRenderRulesetUsesIsolatedTableAndDirectionalCounters(t *testing.T) {
	cfg := Config{Enabled: true, ListenInterface: "ens18", Rules: []Rule{{
		ID: "rule-one", Name: "dwtw", Enabled: true, Protocol: ProtocolTCPUDP,
		ListenPort: 55331, TargetAddress: "78.105.182.150", TargetPort: 54320,
	}}}
	ruleset := renderRuleset(cfg, "ens18", map[string]string{"78.105.182.150": "ens18"}, strings.Repeat("a", 64), false)
	for _, expected := range []string{
		"table ip remnanode_forward",
		"tcp dport 55331",
		"udp dport 55331",
		"dnat to 78.105.182.150:54320 comment",
		"ct status dnat",
		"counter name",
		"_up",
		"_down",
	} {
		if !strings.Contains(ruleset, expected) {
			t.Fatalf("ruleset missing %q:\n%s", expected, ruleset)
		}
	}
	if strings.Contains(ruleset, "flush ruleset") || strings.Contains(ruleset, "table inet remnanode") {
		t.Fatalf("ruleset touches unrelated nftables state:\n%s", ruleset)
	}
}

func TestHostAllowCommentIsStable(t *testing.T) {
	got := hostAllowComment("01989d90-cd3a-7e24-9ab2-a37b39acde11", "tcp", "up")
	want := "remnanode-forward-host-allow:01989d90-cd3a-7e24-9ab2-a37b39acde11:tcp:up"
	if got != want {
		t.Fatalf("unexpected host allow comment: %q", got)
	}
}

func TestRenderHostFirewallRulesUsesDedicatedDockerUserChain(t *testing.T) {
	cfg := Config{Enabled: true, ListenInterface: "ens18", Rules: []Rule{{
		ID: "rule-one", Name: "nlfra", Enabled: true, Protocol: ProtocolTCPUDP,
		ListenPort: 54321, TargetAddress: "82.39.212.176", TargetPort: 54332,
	}}}
	ruleset := renderHostFirewallRules(cfg, "ens18", map[string]string{"82.39.212.176": "ens18"}, true, true)
	for _, expected := range []string{
		"add chain ip filter REMNANODE_FORWARD",
		"insert rule ip filter DOCKER-USER jump REMNANODE_FORWARD",
		"tcp dport 54332 ct original proto-dst 54321",
		"udp dport 54332 ct original proto-dst 54321",
		"tcp sport 54332 ct original proto-dst 54321",
		"remnanode-forward-host-allow:rule-one:tcp:up",
		"remnanode-forward-host-allow:rule-one:udp:down",
	} {
		if !strings.Contains(ruleset, expected) {
			t.Fatalf("host ruleset missing %q:\n%s", expected, ruleset)
		}
	}
	if strings.Contains(ruleset, "flush chain ip filter DOCKER-USER") || strings.Contains(ruleset, "flush table") {
		t.Fatalf("host ruleset touches unrelated firewall state:\n%s", ruleset)
	}
}

func TestResolveTargetIPv4SupportsHostnameAndKeepsCurrentAddress(t *testing.T) {
	service := New(t.TempDir()+"/forwarding.json", 2222, nil)
	service.lookupIP = func(_ context.Context, network, host string) ([]net.IP, error) {
		if network != "ip4" || host != "edge.example.com" {
			t.Fatalf("unexpected lookup: %s %s", network, host)
		}
		return []net.IP{net.ParseIP("198.51.100.11"), net.ParseIP("198.51.100.10")}, nil
	}

	resolved, err := service.resolveTargetIPv4(context.Background(), "edge.example.com", "198.51.100.10")
	if err != nil {
		t.Fatalf("resolveTargetIPv4() error = %v", err)
	}
	if resolved != "198.51.100.10" {
		t.Fatalf("resolveTargetIPv4() = %q, want the still-valid current address", resolved)
	}
}

func TestResolveTargetIPv4ReportsDNSFailure(t *testing.T) {
	service := New(t.TempDir()+"/forwarding.json", 2222, nil)
	service.lookupIP = func(context.Context, string, string) ([]net.IP, error) {
		return nil, errors.New("host not found")
	}
	_, err := service.resolveTargetIPv4(context.Background(), "missing.example.com", "")
	if err == nil || !strings.Contains(err.Error(), "missing.example.com") {
		t.Fatalf("expected a useful DNS error, got %v", err)
	}
}

func TestNormalizeConfigCanonicalizesHostname(t *testing.T) {
	cfg := normalizeConfig(Config{Rules: []Rule{{TargetAddress: " Edge.Example.COM. "}}})
	if got := cfg.Rules[0].TargetAddress; got != "edge.example.com" {
		t.Fatalf("normalized targetAddress = %q", got)
	}
}

func TestValidHostname(t *testing.T) {
	for _, value := range []string{"edge.example.com", "xn--fiqs8s.example", "internal-node"} {
		if !isValidHostname(value) {
			t.Errorf("expected %q to be valid", value)
		}
	}
	for _, value := range []string{"", "-edge.example.com", "edge..example.com", "999.999.999.999", "edge_example.com"} {
		if isValidHostname(value) {
			t.Errorf("expected %q to be invalid", value)
		}
	}
}
