package coreapi

import (
	"bytes"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/protoadapt"
)

func TestSingBoxStatsServiceMatchesUpstreamAPI(t *testing.T) {
	// sing-box keeps its protobuf package name, but overrides the registered
	// service name to this legacy V2Ray path for client compatibility.
	if got, want := singBoxStatsService, "v2ray.core.app.stats.command.StatsService"; got != want {
		t.Fatalf("sing-box stats service = %q, want %q", got, want)
	}
}

func TestSingBoxQueryStatsRequestUsesPatternsField(t *testing.T) {
	request := &singBoxQueryStatsRequest{Patterns: []string{"user>>>"}, Reset_: true}
	wire, err := proto.Marshal(protoadapt.MessageV2Of(request))
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	if bytes.Contains(wire, []byte{0x0a}) {
		t.Fatalf("request unexpectedly contains deprecated pattern field 1: %x", wire)
	}
	if !bytes.Contains(wire, []byte{0x1a, 0x07, 'u', 's', 'e', 'r', '>', '>', '>'}) {
		t.Fatalf("request does not contain patterns field 3: %x", wire)
	}
}
