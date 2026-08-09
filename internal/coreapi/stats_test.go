package coreapi

import "testing"

func TestSingBoxStatsServiceMatchesUpstreamAPI(t *testing.T) {
	// sing-box keeps its protobuf package name, but overrides the registered
	// service name to this legacy V2Ray path for client compatibility.
	if got, want := singBoxStatsService, "v2ray.core.app.stats.command.StatsService"; got != want {
		t.Fatalf("sing-box stats service = %q, want %q", got, want)
	}
}
