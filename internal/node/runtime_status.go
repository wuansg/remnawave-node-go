package node

import (
	"context"
	"time"

	"github.com/remnawave/remnawave-node-go/internal/forwarding"
	"github.com/remnawave/remnawave-node-go/internal/state"
	"github.com/remnawave/remnawave-node-go/internal/usagesnapshot"
)

const (
	RuntimeModeCapability      = "runtime_mode_v1"
	SingBoxCapability          = "core_sing_box_v1"
	SyncStateCapability        = "sync_state_v1"
	PluginCompileCapability    = "plugin_compile_v1"
	PluginDNSStatusCapability  = "plugin_dns_status_v1"
	NetworkInventoryCapability = "network_inventory_v1"
)

type RuntimeMode string

const (
	RuntimeModeCoreActive     RuntimeMode = "CORE_ACTIVE"
	RuntimeModeForwardingOnly RuntimeMode = "FORWARDING_ONLY"
	RuntimeModeIdle           RuntimeMode = "IDLE"
	RuntimeModeDegraded       RuntimeMode = "DEGRADED"
)

type usageSnapshotRuntimeStatus struct {
	Supported bool `json:"supported"`
	Active    bool `json:"active"`
	Enabled   bool `json:"enabled"`
	Capturing bool `json:"capturing"`
}

type agentRuntimeStatus struct {
	Mode           RuntimeMode                `json:"mode"`
	RunningCore    any                        `json:"runningCore"`
	CoreOnline     bool                       `json:"coreOnline"`
	Capabilities   []string                   `json:"capabilities"`
	SupportedCores []string                   `json:"supportedCores"`
	Forwarding     forwarding.RuntimeSummary  `json:"forwarding"`
	UsageSnapshot  usageSnapshotRuntimeStatus `json:"usageSnapshot"`
	Plugin         pluginRuntimeStatus        `json:"plugin"`
	ConfigHashes   state.StartHashes          `json:"configHashes"`
}

type pluginRuntimeStatus struct {
	ConfigHash        string                            `json:"configHash"`
	ActivePlugin      *state.PluginMeta                 `json:"activePlugin"`
	AppliedAt         *time.Time                        `json:"appliedAt,omitempty"`
	LastAttemptAt     *time.Time                        `json:"lastAttemptAt,omitempty"`
	LastError         string                            `json:"lastError,omitempty"`
	DomainResolutions map[string]state.DomainResolution `json:"domainResolutions"`
}

func (m *Manager) runtimeStatus(ctx context.Context) agentRuntimeStatus {
	runningCore := m.state.RunningCoreType()
	coreOnline := runningCore == state.CoreTypeSingBox && m.state.OnlineStatus()

	forwardingStatus := forwarding.RuntimeSummary{
		State:      "unsupported",
		DNSResults: map[string]string{},
	}
	capabilities := []string{RuntimeModeCapability, SingBoxCapability, SyncStateCapability, PluginCompileCapability, PluginDNSStatusCapability, NetworkInventoryCapability, "geocheck_v1"}
	if m.forwarding != nil {
		forwardingStatus = m.forwarding.RuntimeSummary(ctx)
		capabilities = append(capabilities, forwarding.Capability, forwarding.DNSCapability)
	}
	usageStatus := usageSnapshotRuntimeStatus{Supported: m.usageSnapshots != nil}
	if m.usageSnapshots != nil {
		usageStatus.Active = m.usageSnapshots.Active()
		usageStatus.Enabled = usageStatus.Active
		usageStatus.Capturing = usageStatus.Active && coreOnline
		capabilities = append(capabilities, usagesnapshot.Capability)
	}

	var runningValue any
	if runningCore != "" {
		runningValue = string(runningCore)
	}

	pluginState := m.state.PluginState()
	return agentRuntimeStatus{
		Mode:           resolveRuntimeMode(runningCore, coreOnline, forwardingStatus.State),
		RunningCore:    runningValue,
		CoreOnline:     coreOnline,
		Capabilities:   capabilities,
		SupportedCores: []string{string(state.CoreTypeSingBox)},
		Forwarding:     forwardingStatus,
		UsageSnapshot:  usageStatus,
		Plugin: pluginRuntimeStatus{
			ConfigHash:        pluginState.ConfigHash,
			ActivePlugin:      pluginState.ActivePlugin,
			AppliedAt:         pluginState.AppliedAt,
			LastAttemptAt:     pluginState.LastAttemptAt,
			LastError:         pluginState.LastError,
			DomainResolutions: pluginState.DomainResolutions,
		},
		ConfigHashes: m.state.LastHashes(),
	}
}

func resolveRuntimeMode(runningCore state.CoreType, coreOnline bool, forwardingState string) RuntimeMode {
	if forwardingState == "error" || forwardingState == "degraded" {
		return RuntimeModeDegraded
	}
	if runningCore != "" {
		if coreOnline {
			return RuntimeModeCoreActive
		}
		return RuntimeModeDegraded
	}
	if forwardingState == "applied" {
		return RuntimeModeForwardingOnly
	}
	return RuntimeModeIdle
}
