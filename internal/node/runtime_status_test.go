package node

import (
	"context"
	"slices"
	"testing"

	"github.com/remnawave/remnawave-node-go/internal/state"
	"github.com/remnawave/remnawave-node-go/internal/supervisor"
	"github.com/remnawave/remnawave-node-go/internal/usagesnapshot"
)

func TestResolveRuntimeMode(t *testing.T) {
	tests := []struct {
		name            string
		runningCore     state.CoreType
		coreOnline      bool
		forwardingState string
		want            RuntimeMode
	}{
		{name: "healthy core", runningCore: state.CoreTypeSingBox, coreOnline: true, forwardingState: "disabled", want: RuntimeModeCoreActive},
		{name: "forwarding only", forwardingState: "applied", want: RuntimeModeForwardingOnly},
		{name: "idle", forwardingState: "disabled", want: RuntimeModeIdle},
		{name: "core offline", runningCore: state.CoreTypeSingBox, forwardingState: "disabled", want: RuntimeModeDegraded},
		{name: "forwarding error", forwardingState: "error", want: RuntimeModeDegraded},
		{name: "forwarding degraded", runningCore: state.CoreTypeSingBox, coreOnline: true, forwardingState: "degraded", want: RuntimeModeDegraded},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveRuntimeMode(tt.runningCore, tt.coreOnline, tt.forwardingState); got != tt.want {
				t.Fatalf("resolveRuntimeMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUsageSnapshotRuntimeStatusSeparatesEnabledFromCapturing(t *testing.T) {
	runtimeState := state.New("3.5.1")
	manager := &Manager{state: runtimeState}

	status := manager.withUsageSnapshotRuntime(usagesnapshot.Status{Active: true})
	if !status.Active || status.Capturing {
		t.Fatalf("coreless status = %+v, want active without capturing", status)
	}

	runtimeState.SetRunningCore(state.CoreTypeSingBox)
	runtimeState.SetOnlineStatus(false, true)
	status = manager.withUsageSnapshotRuntime(usagesnapshot.Status{Active: true})
	if !status.Active || !status.Capturing {
		t.Fatalf("online sing-box status = %+v, want active and capturing", status)
	}
}

func TestHealthcheckPublishesRuntimeCapabilities(t *testing.T) {
	runtimeState := state.New("3.4.0")
	runtimeState.SetRunningCore(state.CoreTypeSingBox)
	fakeSupervisor := newFakeProcessSupervisor()
	fakeSupervisor.states[singBoxProcessName] = supervisor.StateRunning
	manager := &Manager{state: runtimeState, supervisor: fakeSupervisor}

	response := manager.Healthcheck(context.Background())["response"].(map[string]any)
	if response["runtimeMode"] != RuntimeModeCoreActive {
		t.Fatalf("runtimeMode = %#v", response["runtimeMode"])
	}
	if response["runningCore"] != string(state.CoreTypeSingBox) {
		t.Fatalf("runningCore = %#v", response["runningCore"])
	}
	capabilities := response["capabilities"].([]string)
	for _, capability := range []string{RuntimeModeCapability, SingBoxCapability, XrayCapability} {
		if !slices.Contains(capabilities, capability) {
			t.Fatalf("capabilities %v do not contain %q", capabilities, capability)
		}
	}
}
