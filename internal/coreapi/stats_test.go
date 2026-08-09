package coreapi

import "testing"

func TestSingBoxStatsServiceMatchesUpstreamAPI(t *testing.T) {
	if got, want := singBoxStatsService, "experimental.v2rayapi.StatsService"; got != want {
		t.Fatalf("sing-box stats service = %q, want %q", got, want)
	}
}
