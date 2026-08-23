package node

import (
	"reflect"
	"testing"

	"github.com/remnawave/remnawave-node-go/internal/state"
)

func TestSharedListsResolveIPCIDRDomainAndPortReferences(t *testing.T) {
	config := map[string]any{
		"sharedLists": []any{
			map[string]any{"name": "ext:networks", "type": "ipList", "items": []any{"10.0.0.0/8", "2001:db8::/32"}},
			map[string]any{"name": "ext:domains", "type": "domainList", "items": []any{"example.com"}},
			map[string]any{"name": "ext:ports", "type": "portList", "items": []any{25.0, 587.0, 25.0}},
		},
		"egressFilter": map[string]any{
			"enabled":        true,
			"blockedIps":     []any{"ext:networks"},
			"blockedDomains": []any{"ext:domains"},
			"blockedPorts":   []any{"ext:ports", 465.0},
		},
	}
	shared := readSharedLists(config)
	var plugin state.PluginState
	configureEgressFilter(&plugin, config, shared)
	if !reflect.DeepEqual(plugin.EgressBlockedBaseIPs, []string{"10.0.0.0/8", "2001:db8::/32"}) {
		t.Fatalf("unexpected IP list: %#v", plugin.EgressBlockedBaseIPs)
	}
	if !reflect.DeepEqual(plugin.EgressBlockedDomains, []string{"example.com"}) {
		t.Fatalf("unexpected domain list: %#v", plugin.EgressBlockedDomains)
	}
	if !reflect.DeepEqual(plugin.EgressBlockedPorts, []int{25, 465, 587}) {
		t.Fatalf("unexpected port list: %#v", plugin.EgressBlockedPorts)
	}
}

func TestNormalizeIPOrCIDR(t *testing.T) {
	tests := []struct {
		input string
		value string
		ipv6  bool
		valid bool
	}{
		{"10.1.2.3", "10.1.2.3", false, true},
		{"10.1.2.3/8", "10.0.0.0/8", false, true},
		{"2001:db8::1/32", "2001:db8::/32", true, true},
		{"invalid", "", false, false},
	}
	for _, test := range tests {
		value, ipv6, valid := normalizeIPOrCIDR(test.input)
		if value != test.value || ipv6 != test.ipv6 || valid != test.valid {
			t.Fatalf("normalizeIPOrCIDR(%q) = (%q, %v, %v)", test.input, value, ipv6, valid)
		}
	}
}

func TestValidateSharedListReferencesRejectsMissingAndWrongTypes(t *testing.T) {
	config := map[string]any{
		"sharedLists": []any{
			map[string]any{"name": "ext:domains", "type": "domainList", "items": []any{"example.com"}},
		},
		"egressFilter": map[string]any{
			"enabled":        true,
			"blockedIps":     []any{"ext:missing"},
			"blockedDomains": []any{"ext:domains"},
		},
	}
	if err := validateSharedListReferences(config, readSharedLists(config)); err == nil {
		t.Fatal("expected a missing shared list to fail validation")
	}

	config["egressFilter"] = map[string]any{
		"enabled":    true,
		"blockedIps": []any{"ext:domains"},
	}
	if err := validateSharedListReferences(config, readSharedLists(config)); err == nil {
		t.Fatal("expected a shared list type mismatch to fail validation")
	}
}
