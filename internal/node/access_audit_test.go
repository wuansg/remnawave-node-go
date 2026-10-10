package node

import (
	"github.com/remnawave/remnawave-node-go/internal/config"
	"testing"
)

func TestAccessAuditAPIConfigurationIsPrivateAndPreservesServices(t *testing.T) {
	cfg := config.Config{SingBoxAPIPort: 61001, SingBoxV2RayAPIPort: 61002, SingBoxAuditAPIPort: 61003, SecretKey: "fixture-private-secret"}
	raw := map[string]any{"services": []any{map[string]any{"type": "resolved", "tag": "keep-me"}}, "inbounds": []any{map[string]any{"type": "anytls", "tag": "fixture"}}}
	got := applySingBoxAPIConfig(raw, cfg)
	got = applySingBoxAPIConfig(got, cfg)
	services := asMapSlice(got["services"])
	if len(services) != 2 || stringValue(services[0]["tag"]) != "keep-me" {
		t.Fatal("Unrelated service was removed or audit service duplicated")
	}
	audit := services[1]
	if stringValue(audit["listen"]) != "127.0.0.1" || stringValue(audit["secret"]) == "" || stringValue(audit["secret"]) == cfg.SecretKey {
		t.Fatal("Audit API must use a private loopback listener and derived secret")
	}
	if _, ok := got["route"]; ok {
		t.Fatal("Audit must not change routing or force sniffing")
	}
	if len(asMapSlice(got["inbounds"])) != 1 {
		t.Fatal("Audit changed inbounds")
	}
}
