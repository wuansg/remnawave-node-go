package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/remnawave/remnawave-node-go/internal/config"
	"github.com/remnawave/remnawave-node-go/internal/coreapi"
	"github.com/remnawave/remnawave-node-go/internal/forwarding"
	"github.com/remnawave/remnawave-node-go/internal/geocheck"
	"github.com/remnawave/remnawave-node-go/internal/state"
	"github.com/remnawave/remnawave-node-go/internal/statname"
	"github.com/remnawave/remnawave-node-go/internal/supervisor"
	"github.com/remnawave/remnawave-node-go/internal/system"
	"github.com/remnawave/remnawave-node-go/internal/usagesnapshot"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	singBoxProcessName = "sing-box"
	nftTableName       = "remnanode"
)

var (
	ErrCoreUnavailable = errors.New("core is not running or its statistics API is unavailable")

	defaultIgnoredIPs = map[string]struct{}{
		"::":              {},
		"::1":             {},
		"0.0.0.0":         {},
		"0.0.0.0/0":       {},
		"127.0.0.0/8":     {},
		"127.0.0.1":       {},
		"255.255.255.255": {},
	}
	singBoxKeyAliases = map[string]string{
		"certificatePath": "certificate_path",
		"domainSuffix":    "domain_suffix",
		"ipIsPrivate":     "ip_is_private",
		"keyPath":         "key_path",
		"listenPort":      "listen_port",
	}
)

type Manager struct {
	cfg                config.Config
	state              *state.Runtime
	logger             *slog.Logger
	supervisor         processSupervisor
	network            *system.NetworkMonitor
	nftReady           bool
	startedAt          time.Time
	coreMu             sync.Mutex
	singStats          coreapi.StatsClient
	usageSnapshots     *usagesnapshot.Store
	forwarding         *forwarding.Service
	geocheck           *geocheck.Runner
	usageMu            sync.Mutex
	usageCoreRestarted bool
	runCommand         commandRunner
	healthTimeout      time.Duration
	healthPollInterval time.Duration
	singBoxApplyResult map[string]any
}

type processSupervisor interface {
	StartProcess(context.Context, string) error
	StopProcess(context.Context, string) error
	GetProcessInfo(context.Context, string) (supervisor.ProcessInfo, error)
}

type commandRunner func(context.Context, string, ...string) ([]byte, error)

const (
	defaultSingBoxHealthTimeout      = 10 * time.Second
	defaultSingBoxHealthPollInterval = 250 * time.Millisecond
)

type StartRequest struct {
	CoreType      string         `json:"coreType"`
	Internals     startInternals `json:"internals"`
	SingBoxConfig map[string]any `json:"singBoxConfig"`
}

type startInternals struct {
	ForceRestart bool              `json:"forceRestart"`
	Hashes       state.StartHashes `json:"hashes"`
}

type AddUserRequest struct {
	Data     []AddUserItem `json:"data"`
	HashData struct {
		VLESSUUID     string `json:"vlessUuid"`
		PrevVLESSUUID string `json:"prevVlessUuid"`
	} `json:"hashData"`
}

type AddUserItem struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	UUID       string `json:"uuid"`
	Flow       string `json:"flow"`
	CipherType int    `json:"cipherType"`
	IVCheck    bool   `json:"ivCheck"`
}

type RemoveUserRequest struct {
	Username string `json:"username"`
	HashData struct {
		VLESSUUID string `json:"vlessUuid"`
	} `json:"hashData"`
}

type AddUsersRequest struct {
	AffectedInboundTags []string      `json:"affectedInboundTags"`
	Users               []BulkAddUser `json:"users"`
}

type BulkAddUser struct {
	InboundData []BulkInboundData `json:"inboundData"`
	UserData    struct {
		UserID         string `json:"userId"`
		HashUUID       string `json:"hashUuid"`
		VLESSUUID      string `json:"vlessUuid"`
		TrojanPassword string `json:"trojanPassword"`
		SSPassword     string `json:"ssPassword"`
	} `json:"userData"`
}

type BulkInboundData struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
	Flow string `json:"flow"`
}

type RemoveUsersRequest struct {
	Users []struct {
		UserID   string `json:"userId"`
		HashUUID string `json:"hashUuid"`
	} `json:"users"`
}

type GetInboundUsersRequest struct {
	Tag string `json:"tag"`
}

type DropUsersConnectionsRequest struct {
	UserIDs []string `json:"userIds"`
}

type DropIPsRequest struct {
	IPs []string `json:"ips"`
}

type GetUserOnlineStatusRequest struct {
	Username string `json:"username"`
}

type GetUsersStatsRequest struct {
	Reset bool `json:"reset"`
}

type GetUsersInboundStatsRequest struct {
	Reset bool `json:"reset"`
}

type GetTagStatsRequest struct {
	Tag   string `json:"tag"`
	Reset bool   `json:"reset"`
}

type GetResetRequest struct {
	Reset bool `json:"reset"`
}

type GetUserIPListRequest struct {
	UserID string `json:"userId"`
}

type VisionIPRequest struct {
	IP string `json:"ip"`
}

type PluginSyncRequest struct {
	ConfigHash string `json:"configHash"`
	Plugin     *struct {
		Config map[string]any `json:"config"`
		UUID   string         `json:"uuid"`
		Name   string         `json:"name"`
	} `json:"plugin"`
}

type BlockIPsRequest struct {
	IPs []struct {
		IP      string `json:"ip"`
		Timeout int    `json:"timeout"`
	} `json:"ips"`
}

type UnblockIPsRequest struct {
	IPs []string `json:"ips"`
}

func NewManager(cfg config.Config, runtimeState *state.Runtime, logger *slog.Logger, client *supervisor.Client, network *system.NetworkMonitor) (*Manager, error) {
	singStats, err := coreapi.NewSingBoxStatsClient(fmt.Sprintf("127.0.0.1:%d", singBoxV2RayAPIPort(cfg)), insecure.NewCredentials())
	if err != nil {
		return nil, err
	}
	usageSnapshots, err := usagesnapshot.Open(cfg.UsageSnapshotDBPath, cfg.UsageSnapshotMaxBytes)
	if err != nil {
		_ = singStats.Close()
		return nil, err
	}
	manager := &Manager{
		cfg:                cfg,
		state:              runtimeState,
		logger:             logger,
		supervisor:         client,
		network:            network,
		nftReady:           commandExists("nft") && hasNetAdmin(),
		startedAt:          time.Now(),
		singStats:          singStats,
		usageSnapshots:     usageSnapshots,
		forwarding:         forwarding.New(cfg.ForwardingStatePath, cfg.NodePort, logger),
		geocheck:           geocheck.New(geocheck.DefaultBinaryPath),
		runCommand:         runCombinedOutput,
		healthTimeout:      defaultSingBoxHealthTimeout,
		healthPollInterval: defaultSingBoxHealthPollInterval,
	}
	if err := manager.forwarding.Restore(context.Background()); err != nil {
		logger.Error("failed to restore forwarding rules", "error", err)
	}
	return manager, nil
}

func (m *Manager) Geocheck(ctx context.Context, request geocheck.Request) (map[string]any, error) {
	return m.geocheck.Run(ctx, request)
}

func (m *Manager) Close() error {
	var first error
	if m.singStats != nil {
		if err := m.singStats.Close(); first == nil {
			first = err
		}
	}
	if m.usageSnapshots != nil {
		if err := m.usageSnapshots.Close(); first == nil {
			first = err
		}
	}
	return first
}

func (m *Manager) SyncEnvironment(ctx context.Context) {
	singBoxVersion := m.readVersion(ctx, "/usr/local/bin/sing-box", "version")
	m.state.SetCoreVersion(singBoxVersion)
	m.refreshOnlineStatus(ctx)
}

// SyncProcessStatus refreshes the inexpensive process state without spawning
// the core binaries to rediscover versions. Versions are stable for the life
// of a container and are loaded by SyncEnvironment at startup/start time.
func (m *Manager) SyncProcessStatus(ctx context.Context) {
	m.refreshOnlineStatus(ctx)
}

func (m *Manager) InternalConfig() map[string]any {
	return m.state.SingBoxConfig()
}

func (m *Manager) Start(ctx context.Context, request StartRequest, remoteIP string) map[string]any {
	m.coreMu.Lock()
	defer m.coreMu.Unlock()

	m.SyncEnvironment(ctx)

	coreType := state.CoreTypeSingBox

	snapshot := system.SystemSnapshot(m.network)
	shouldRestart := m.shouldRestartCore(coreType, request.Internals.ForceRestart, request.Internals.Hashes)

	config := applySingBoxAPIConfig(normalizeSingBoxKeys(cloneMap(request.SingBoxConfig)), m.cfg)
	if len(config) == 0 {
		return wrapStartResponse(false, nil, ptrString("singBoxConfig is required for SING_BOX core"), m.state.NodeVersion(), snapshot, string(coreType), m.coreVersions(), nil)
	}
	if err := m.forwarding.ValidateCoreConfig(string(coreType), config); err != nil {
		return m.coreConflictResponse(ctx, err)
	}
	shouldRestart = shouldRestart || !reflect.DeepEqual(m.state.SingBoxConfig(), config)
	if shouldRestart {
		if err := m.restartSingBox(ctx, config); err != nil {
			return m.coreActivationFailureResponse(ctx, err, snapshot)
		}
	} else {
		m.state.SetSingBoxConfig(config)
		m.recordUnchangedSingBoxConfig(config)
	}

	m.state.SetLastHashes(request.Internals.Hashes)
	m.refreshOnlineStatus(ctx)
	started := m.state.OnlineStatus()
	m.logger.Info("node start request handled", "core", coreType, "remote_ip", remoteIP, "restarted", shouldRestart)
	if shouldRestart && m.UsageSnapshotActive() {
		m.usageMu.Lock()
		m.usageCoreRestarted = true
		m.usageMu.Unlock()
	}
	return wrapStartResponse(started, m.activeVersion(coreType), nil, m.state.NodeVersion(), snapshot, string(coreType), m.coreVersions(), m.startConfigApplyResult(coreType))
}

func (m *Manager) coreActivationFailureResponse(ctx context.Context, err error, snapshot system.Snapshot) map[string]any {
	m.refreshOnlineStatus(ctx)
	running := m.state.RunningCoreType()
	started := m.state.OnlineStatus()
	return wrapStartResponse(started, m.activeVersion(running), ptrString(err.Error()), m.state.NodeVersion(), snapshot, string(running), m.coreVersions(), m.singBoxApplyResult)
}

func (m *Manager) coreConflictResponse(ctx context.Context, err error) map[string]any {
	m.refreshOnlineStatus(ctx)
	running := m.state.RunningCoreType()
	started := m.state.OnlineStatus()
	return wrapStartResponse(started, m.activeVersion(running), ptrString(err.Error()), m.state.NodeVersion(), system.SystemSnapshot(m.network), string(running), m.coreVersions(), nil)
}

func (m *Manager) shouldRestartCore(coreType state.CoreType, force bool, hashes state.StartHashes) bool {
	targetOnline := m.state.OnlineStatus()
	return force ||
		m.cfg.DisableHashCheck ||
		m.state.RunningCoreType() != coreType ||
		!targetOnline ||
		m.state.ShouldRestart(hashes)
}

func (m *Manager) Stop(ctx context.Context) map[string]any {
	m.coreMu.Lock()
	defer m.coreMu.Unlock()

	_ = m.supervisor.StopProcess(ctx, singBoxProcessName)
	m.state.SetRunningCore("")
	m.state.SetOnlineStatus(false)
	m.state.Reset()
	return map[string]any{"response": map[string]any{"isStopped": true}}
}

func (m *Manager) Healthcheck(ctx context.Context) map[string]any {
	m.refreshOnlineStatus(ctx)
	runtimeStatus := m.runtimeStatus(ctx)
	return map[string]any{
		"response": map[string]any{
			"isAlive":           true,
			"architecture":      runtime.GOARCH,
			"runningCore":       runtimeStatus.RunningCore,
			"supportedCores":    runtimeStatus.SupportedCores,
			"coreVersions":      m.coreVersions(),
			"nodeVersion":       m.state.NodeVersion(),
			"capabilities":      runtimeStatus.Capabilities,
			"runtimeMode":       runtimeStatus.Mode,
			"coreOnline":        runtimeStatus.CoreOnline,
			"forwarding":        runtimeStatus.Forwarding,
			"usageSnapshot":     runtimeStatus.UsageSnapshot,
			"plugin":            runtimeStatus.Plugin,
			"configHashes":      runtimeStatus.ConfigHashes,
			"networkInterfaces": system.NetworkInterfaces(),
		},
	}
}

func (m *Manager) ForwardingValidate(ctx context.Context, request forwarding.SyncRequest) error {
	m.coreMu.Lock()
	defer m.coreMu.Unlock()
	return m.forwarding.Validate(ctx, request.Config, m.currentCoreListeners())
}

func (m *Manager) ForwardingSync(ctx context.Context, request forwarding.SyncRequest) (forwarding.Status, error) {
	m.coreMu.Lock()
	defer m.coreMu.Unlock()
	return m.forwarding.SyncWithHash(ctx, request.Config, m.currentCoreListeners(), request.ConfigHash)
}

func (m *Manager) ForwardingStatus(ctx context.Context) forwarding.Status {
	return m.forwarding.Status(ctx)
}

func (m *Manager) RefreshForwardingDNS(ctx context.Context) {
	m.coreMu.Lock()
	defer m.coreMu.Unlock()
	refreshCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	if err := m.forwarding.RefreshDNS(refreshCtx, m.currentCoreListeners()); err != nil {
		m.logger.Warn("failed to refresh forwarding DNS targets", "error", err)
	}
	previousPluginState := m.state.PluginState()
	pluginState := previousPluginState
	previous := append([]string(nil), pluginState.EgressBlockedIPs...)
	if err := resolveEgressDomains(refreshCtx, &pluginState, &previousPluginState); err != nil {
		m.logger.Warn("failed to refresh plugin egress DNS targets", "error", err)
		now := time.Now().UTC()
		previousPluginState.LastAttemptAt = &now
		previousPluginState.LastError = err.Error()
		m.state.SetPluginState(previousPluginState)
	} else if !reflect.DeepEqual(previous, pluginState.EgressBlockedIPs) {
		if err := m.syncNFTState(refreshCtx, pluginState); err != nil {
			m.logger.Warn("failed to apply refreshed plugin egress DNS targets", "error", err)
			m.restorePluginNFTState(previousPluginState)
			pluginState = previousPluginState
			pluginState.LastAttemptAt = ptrTime(time.Now().UTC())
			pluginState.LastError = err.Error()
			m.state.SetPluginState(pluginState)
		} else {
			pluginState.LastError = ""
			m.state.SetPluginState(pluginState)
		}
	} else {
		pluginState.LastError = ""
		m.state.SetPluginState(pluginState)
	}
}

func (m *Manager) currentCoreListeners() []forwarding.Listener {
	if m.state.RunningCoreType() == state.CoreTypeSingBox {
		return forwarding.ExtractCoreListeners(string(state.CoreTypeSingBox), m.state.SingBoxConfig())
	}
	return nil
}

func (m *Manager) UsageSnapshotActive() bool {
	return m.usageSnapshots != nil && m.usageSnapshots.Active()
}

func (m *Manager) ActivateUsageSnapshots(ctx context.Context) (usagesnapshot.Status, error) {
	if m.usageSnapshots == nil {
		return usagesnapshot.Status{}, errors.New("usage snapshot storage is unavailable")
	}
	counters, err := m.currentUsageCounters(ctx)
	if err != nil {
		return usagesnapshot.Status{}, err
	}
	status, err := m.usageSnapshots.Activate(counters)
	return m.withUsageSnapshotRuntime(status), err
}

func (m *Manager) CaptureUsageSnapshot(ctx context.Context) {
	if !m.UsageSnapshotActive() {
		return
	}
	// Forwarding-only and idle nodes intentionally have no core stats API. Keep
	// the snapshot generation intact so it can resume with the next core, but do
	// not emit a false warning on every capture tick.
	if m.state.RunningCoreType() == "" {
		return
	}
	counters, err := m.currentUsageCounters(ctx)
	if err != nil {
		m.logger.Warn("failed to capture usage snapshot", "error", err)
		return
	}
	m.usageMu.Lock()
	coreRestarted := m.usageCoreRestarted
	m.usageCoreRestarted = false
	m.usageMu.Unlock()
	if err := m.usageSnapshots.Capture(string(m.state.RunningCoreType()), counters, time.Now(), coreRestarted); err != nil && !errors.Is(err, usagesnapshot.ErrNotActive) {
		if coreRestarted {
			m.usageMu.Lock()
			m.usageCoreRestarted = true
			m.usageMu.Unlock()
		}
		m.logger.Error("failed to persist usage snapshot", "error", err)
	}
}

func (m *Manager) PullUsageSnapshots(request usagesnapshot.PullRequest) (usagesnapshot.PullResponse, error) {
	if m.usageSnapshots == nil {
		return usagesnapshot.PullResponse{}, errors.New("usage snapshot storage is unavailable")
	}
	return m.usageSnapshots.Pull(request)
}

func (m *Manager) AckUsageSnapshots(request usagesnapshot.AckRequest) (usagesnapshot.Status, error) {
	if m.usageSnapshots == nil {
		return usagesnapshot.Status{}, errors.New("usage snapshot storage is unavailable")
	}
	status, err := m.usageSnapshots.Ack(request)
	return m.withUsageSnapshotRuntime(status), err
}

func (m *Manager) UsageSnapshotStatus() (usagesnapshot.Status, error) {
	if m.usageSnapshots == nil {
		return usagesnapshot.Status{}, errors.New("usage snapshot storage is unavailable")
	}
	status, err := m.usageSnapshots.Status()
	return m.withUsageSnapshotRuntime(status), err
}

func (m *Manager) withUsageSnapshotRuntime(status usagesnapshot.Status) usagesnapshot.Status {
	if !status.Active {
		return status
	}
	runningCore := m.state.RunningCoreType()
	status.Capturing = runningCore == state.CoreTypeSingBox && m.state.OnlineStatus()
	return status
}

func (m *Manager) currentUsageCounters(ctx context.Context) ([]usagesnapshot.Counter, error) {
	client := m.statsClient()
	if client == nil || m.state.RunningCoreType() == "" {
		return nil, ErrCoreUnavailable
	}
	result := make([]usagesnapshot.Counter, 0)
	users := m.queryUserInboundStats(ctx, false)
	for _, item := range users {
		for _, direction := range []string{"uplink", "downlink"} {
			result = append(result, usagesnapshot.Counter{Kind: "user", Name: item["username"].(string), Inbound: item["inbound"].(string), Direction: direction, Value: item[direction].(int64)})
		}
	}
	for _, kind := range []string{"inbound", "outbound"} {
		items := m.queryGroupedStats(ctx, kind, kind+">>>", false)
		for _, item := range items {
			for _, direction := range []string{"uplink", "downlink"} {
				result = append(result, usagesnapshot.Counter{Kind: kind, Name: item[kind].(string), Direction: direction, Value: item[direction].(int64)})
			}
		}
	}
	return result, nil
}

func (m *Manager) GetSystemStats(ctx context.Context) (map[string]any, error) {
	runningCore := m.state.RunningCoreType()
	if runningCore == "" || !m.state.OnlineStatus() {
		return nil, ErrCoreUnavailable
	}

	client := m.statsClient()
	if client == nil {
		return nil, ErrCoreUnavailable
	}
	stats, err := client.System(ctx)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCoreUnavailable, err)
	}

	snapshot := system.SystemSnapshot(m.network)
	pluginState := m.state.PluginState()
	coreStats := map[string]any{
		"numGoroutine": stats.NumGoroutine,
		"numGC":        stats.NumGC,
		"alloc":        stats.Alloc,
		"totalAlloc":   stats.TotalAlloc,
		"sys":          stats.Sys,
		"mallocs":      stats.Mallocs,
		"frees":        stats.Frees,
		"liveObjects":  stats.LiveObjects,
		"pauseTotalNs": stats.PauseTotalNs,
		"uptime":       stats.Uptime,
	}
	return map[string]any{
		"response": map[string]any{
			"coreInfo": coreStats,
			"plugins": map[string]any{
				"torrentBlocker": map[string]any{
					"reportsCount": len(pluginState.TorrentReports),
				},
			},
			"system": map[string]any{
				"stats": snapshot.Stats,
			},
		},
	}, nil
}

func (m *Manager) GetUserOnlineStatus(ctx context.Context, request GetUserOnlineStatusRequest) map[string]any {
	online, err := m.userConnectionProvider().UserOnlineStatus(ctx, request.Username)
	if err != nil {
		online = false
	}
	return map[string]any{"response": map[string]any{"isOnline": online}}
}

func (m *Manager) GetUsersStats(ctx context.Context, request GetUsersStatsRequest) map[string]any {
	userInboundStats := m.queryUserInboundStats(ctx, request.Reset)
	grouped := map[string]map[string]any{}
	for _, user := range userInboundStats {
		username := user["username"].(string)
		item := grouped[username]
		if item == nil {
			item = map[string]any{"username": username, "uplink": int64(0), "downlink": int64(0)}
			grouped[username] = item
		}
		item["uplink"] = item["uplink"].(int64) + user["uplink"].(int64)
		item["downlink"] = item["downlink"].(int64) + user["downlink"].(int64)
	}
	users := make([]map[string]any, 0, len(grouped))
	for _, user := range grouped {
		if user["uplink"].(int64) != 0 || user["downlink"].(int64) != 0 {
			users = append(users, user)
		}
	}
	sort.Slice(users, func(i, j int) bool { return users[i]["username"].(string) < users[j]["username"].(string) })
	return map[string]any{"response": map[string]any{"users": users}}
}

func (m *Manager) GetUsersInboundStats(ctx context.Context, request GetUsersInboundStatsRequest) map[string]any {
	users := m.queryUserInboundStats(ctx, request.Reset)
	filtered := users[:0]
	for _, user := range users {
		if user["uplink"].(int64) != 0 || user["downlink"].(int64) != 0 {
			filtered = append(filtered, user)
		}
	}
	return map[string]any{"response": map[string]any{"users": filtered}}
}

func (m *Manager) GetInboundStats(ctx context.Context, request GetTagStatsRequest) map[string]any {
	items := m.queryGroupedStats(ctx, "inbound", "inbound>>>"+request.Tag+">>>", request.Reset)
	return map[string]any{"response": findTagStats(items, "inbound", request.Tag)}
}

func (m *Manager) GetOutboundStats(ctx context.Context, request GetTagStatsRequest) map[string]any {
	items := m.queryGroupedStats(ctx, "outbound", "outbound>>>"+request.Tag+">>>", request.Reset)
	return map[string]any{"response": findTagStats(items, "outbound", request.Tag)}
}

func (m *Manager) GetAllInboundStats(ctx context.Context, request GetResetRequest) map[string]any {
	items := m.queryGroupedStats(ctx, "inbound", "inbound>>>", request.Reset)
	return map[string]any{"response": map[string]any{"inbounds": items}}
}

func (m *Manager) GetAllOutboundStats(ctx context.Context, request GetResetRequest) map[string]any {
	items := m.queryGroupedStats(ctx, "outbound", "outbound>>>", request.Reset)
	return map[string]any{"response": map[string]any{"outbounds": items}}
}

func (m *Manager) GetCombinedStats(ctx context.Context, request GetResetRequest) map[string]any {
	inbounds := m.queryGroupedStats(ctx, "inbound", "inbound>>>", request.Reset)
	outbounds := m.queryGroupedStats(ctx, "outbound", "outbound>>>", request.Reset)
	return map[string]any{"response": map[string]any{"inbounds": inbounds, "outbounds": outbounds}}
}

func (m *Manager) statsClient() coreapi.StatsClient {
	if m.state.RunningCoreType() == state.CoreTypeSingBox {
		return m.singStats
	}
	return nil
}

func (m *Manager) queryGroupedStats(ctx context.Context, kind, pattern string, reset bool) []map[string]any {
	client := m.statsClient()
	if client == nil {
		return []map[string]any{}
	}
	stats, err := client.Query(ctx, pattern, reset)
	if err != nil {
		m.logger.Warn("failed to query core traffic stats", "pattern", pattern, "error", err)
		return []map[string]any{}
	}
	grouped := map[string]map[string]any{}
	prefix := kind + ">>>"
	marker := ">>>traffic>>>"
	for _, stat := range stats {
		if !strings.HasPrefix(stat.Name, prefix) {
			continue
		}
		remainder := strings.TrimPrefix(stat.Name, prefix)
		idx := strings.LastIndex(remainder, marker)
		if idx <= 0 {
			continue
		}
		tag, direction := remainder[:idx], remainder[idx+len(marker):]
		if direction != "uplink" && direction != "downlink" {
			continue
		}
		item := grouped[tag]
		if item == nil {
			item = map[string]any{kind: tag, "uplink": int64(0), "downlink": int64(0)}
			if kind == "user" {
				delete(item, "user")
				item["username"] = tag
			}
			grouped[tag] = item
		}
		item[direction] = item[direction].(int64) + stat.Value
	}
	items := make([]map[string]any, 0, len(grouped))
	for _, item := range grouped {
		items = append(items, item)
	}
	key := kind
	if kind == "user" {
		key = "username"
	}
	sort.Slice(items, func(i, j int) bool { return items[i][key].(string) < items[j][key].(string) })
	return items
}

func (m *Manager) queryUserInboundStats(ctx context.Context, reset bool) []map[string]any {
	client := m.statsClient()
	if client == nil {
		return []map[string]any{}
	}

	stats, err := client.Query(ctx, "user>>>", reset)
	if err != nil {
		m.logger.Warn("failed to query core user traffic stats", "error", err)
		return []map[string]any{}
	}

	grouped := map[string]map[string]any{}
	prefix := "user>>>"
	marker := ">>>traffic>>>"
	for _, stat := range stats {
		if !strings.HasPrefix(stat.Name, prefix) {
			continue
		}

		remainder := strings.TrimPrefix(stat.Name, prefix)
		idx := strings.LastIndex(remainder, marker)
		if idx <= 0 {
			continue
		}

		rawUsername, direction := remainder[:idx], remainder[idx+len(marker):]
		if direction != "uplink" && direction != "downlink" {
			continue
		}

		username, inbound, ok := statname.ParseUserInbound(rawUsername)
		if !ok {
			username = rawUsername
			inbound = ""
		}

		key := username + "\x00" + inbound
		item := grouped[key]
		if item == nil {
			item = map[string]any{
				"username": username,
				"inbound":  inbound,
				"uplink":   int64(0),
				"downlink": int64(0),
			}
			grouped[key] = item
		}
		item[direction] = item[direction].(int64) + stat.Value
	}

	items := make([]map[string]any, 0, len(grouped))
	for _, item := range grouped {
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
		leftUser, rightUser := items[i]["username"].(string), items[j]["username"].(string)
		if leftUser != rightUser {
			return leftUser < rightUser
		}
		return items[i]["inbound"].(string) < items[j]["inbound"].(string)
	})

	return items
}

func findTagStats(items []map[string]any, kind, tag string) map[string]any {
	for _, item := range items {
		if item[kind] == tag {
			return item
		}
	}
	return map[string]any{kind: tag, "uplink": int64(0), "downlink": int64(0)}
}

func (m *Manager) GetUserIPList(ctx context.Context, request GetUserIPListRequest) map[string]any {
	items, err := m.userConnectionProvider().UserIPList(ctx, request.UserID)
	if err != nil {
		return map[string]any{"response": map[string]any{"ips": []map[string]any{}}}
	}
	return map[string]any{"response": map[string]any{"ips": formatSeenIPs(items)}}
}

func (m *Manager) GetUsersIPList(ctx context.Context) map[string]any {
	items, err := m.userConnectionProvider().UsersIPList(ctx)
	if err != nil {
		return map[string]any{"response": map[string]any{"users": []map[string]any{}}}
	}
	return map[string]any{"response": map[string]any{"users": formatUserIPLists(items)}}
}

func (m *Manager) GetInboundUsers(ctx context.Context, request GetInboundUsersRequest) map[string]any {
	users := []map[string]any{}
	for _, user := range m.state.InboundUsers(request.Tag) {
		users = append(users, map[string]any{
			"email":    user.UserID,
			"username": user.UserID,
		})
	}
	return map[string]any{"response": map[string]any{"users": users}}
}

func (m *Manager) GetInboundUsersCount(ctx context.Context, request GetInboundUsersRequest) map[string]any {
	return map[string]any{"response": map[string]any{"count": len(m.state.InboundUsers(request.Tag))}}
}

func (m *Manager) AddUser(ctx context.Context, request AddUserRequest) map[string]any {
	m.coreMu.Lock()
	defer m.coreMu.Unlock()

	if err := m.applyAddUserRequest(request); err != nil {
		return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
	}
	if err := m.restartCurrentCore(ctx); err != nil {
		return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
	}
	return map[string]any{"response": map[string]any{"success": true, "error": nil}}
}

func (m *Manager) AddUsers(ctx context.Context, request AddUsersRequest) map[string]any {
	m.coreMu.Lock()
	defer m.coreMu.Unlock()

	if err := m.applyAddUsersRequest(request); err != nil {
		return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
	}
	if err := m.restartCurrentCore(ctx); err != nil {
		return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
	}
	return map[string]any{"response": map[string]any{"success": true, "error": nil}}
}

func (m *Manager) RemoveUser(ctx context.Context, request RemoveUserRequest) map[string]any {
	m.coreMu.Lock()
	defer m.coreMu.Unlock()

	if err := m.removeUserEverywhere(request.Username); err != nil {
		return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
	}
	if err := m.restartCurrentCore(ctx); err != nil {
		return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
	}
	return map[string]any{"response": map[string]any{"success": true, "error": nil}}
}

func (m *Manager) RemoveUsers(ctx context.Context, request RemoveUsersRequest) map[string]any {
	m.coreMu.Lock()
	defer m.coreMu.Unlock()

	for _, user := range request.Users {
		if err := m.removeUserEverywhere(user.UserID); err != nil {
			return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
		}
	}
	if err := m.restartCurrentCore(ctx); err != nil {
		return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
	}
	return map[string]any{"response": map[string]any{"success": true, "error": nil}}
}

func (m *Manager) DropUsersConnections(ctx context.Context, request DropUsersConnectionsRequest) map[string]any {
	provider := m.userConnectionProvider()
	for _, userID := range request.UserIDs {
		if closer, ok := provider.(UserConnectionCloser); ok {
			if err := closer.CloseUserConnections(ctx, userID); err == nil {
				continue
			}
		}
		items, err := provider.UserIPList(ctx, userID)
		if err != nil {
			continue
		}
		for _, item := range items {
			m.dropConnections(item.IP)
		}
	}
	return map[string]any{"response": map[string]any{"success": true}}
}

func (m *Manager) userConnectionProvider() UserConnectionProvider {
	return newUserConnectionProvider(m.cfg.SingBoxAPIPort, m.cfg.InternalRESTToken)
}

func formatSeenIPs(items []state.SeenIP) []map[string]any {
	out := make([]map[string]any, 0, len(items))
	for _, ip := range items {
		out = append(out, map[string]any{
			"ip":       ip.IP,
			"lastSeen": ip.LastSeen.Format(time.RFC3339),
		})
	}
	return out
}

func formatUserIPLists(items map[string][]state.SeenIP) []map[string]any {
	users := make([]map[string]any, 0, len(items))
	for userID, seenIPs := range items {
		users = append(users, map[string]any{
			"userId": userID,
			"ips":    formatSeenIPs(seenIPs),
		})
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i]["userId"].(string) < users[j]["userId"].(string)
	})
	return users
}

func (m *Manager) DropIPs(request DropIPsRequest) map[string]any {
	for _, ip := range request.IPs {
		m.dropConnections(ip)
	}
	return map[string]any{"response": map[string]any{"success": true}}
}

func (m *Manager) BlockIP(ctx context.Context, request VisionIPRequest) map[string]any {
	return map[string]any{"response": map[string]any{"success": false, "error": "Vision routing is no longer supported"}}
}

func (m *Manager) UnblockIP(ctx context.Context, request VisionIPRequest) map[string]any {
	return map[string]any{"response": map[string]any{"success": false, "error": "Vision routing is no longer supported"}}
}

func (m *Manager) SyncPlugin(ctx context.Context, request PluginSyncRequest) map[string]any {
	m.coreMu.Lock()
	defer m.coreMu.Unlock()

	current := m.state.PluginState()
	if request.Plugin == nil {
		current = emptyPluginState()
		now := time.Now().UTC()
		current.LastAttemptAt = &now
		if m.nftReady {
			if err := m.recreateNFTables(ctx); err != nil {
				current.LastError = err.Error()
				m.state.SetPluginState(current)
				return map[string]any{"response": map[string]any{"accepted": false, "error": err.Error()}}
			}
		}
		current.AppliedAt = &now
		m.state.SetPluginState(current)
		return map[string]any{"response": map[string]any{"accepted": true, "configHash": ""}}
	}

	next, err := compilePluginState(ctx, request, &current)
	if err != nil {
		now := time.Now().UTC()
		current.LastAttemptAt = &now
		current.LastError = err.Error()
		m.state.SetPluginState(current)
		return map[string]any{"response": map[string]any{"accepted": false, "error": err.Error()}}
	}

	changedTorrent := current.TorrentEnabled != next.TorrentEnabled || current.TorrentDuration != next.TorrentDuration || !sameStringSet(current.TorrentIncludeRuleTags, next.TorrentIncludeRuleTags)
	if m.nftReady {
		if err := m.applyPluginNFTState(ctx, next, current); err != nil {
			now := time.Now().UTC()
			current.LastAttemptAt = &now
			current.LastError = err.Error()
			m.state.SetPluginState(current)
			return map[string]any{"response": map[string]any{"accepted": false, "error": err.Error()}}
		}
	}
	m.state.SetPluginState(next)
	if changedTorrent {
		if err := m.restartCurrentCore(ctx); err != nil {
			m.state.SetPluginState(current)
			m.restorePluginNFTState(current)
			rollbackCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if rollbackErr := m.restartCurrentCore(rollbackCtx); rollbackErr != nil {
				m.logger.Error("failed to restart core after plugin rollback", "error", rollbackErr)
			}
			current.LastAttemptAt = ptrTime(time.Now().UTC())
			current.LastError = err.Error()
			m.state.SetPluginState(current)
			return map[string]any{"response": map[string]any{"accepted": false, "error": err.Error(), "rolledBack": true}}
		}
	}
	now := time.Now().UTC()
	next.AppliedAt = &now
	next.LastAttemptAt = &now
	next.LastError = ""
	m.state.SetPluginState(next)
	return map[string]any{"response": map[string]any{"accepted": true, "configHash": next.ConfigHash, "appliedAt": now}}
}

func (m *Manager) CompilePlugin(ctx context.Context, request PluginSyncRequest) map[string]any {
	m.coreMu.Lock()
	defer m.coreMu.Unlock()
	if request.Plugin == nil {
		return map[string]any{"response": map[string]any{
			"accepted": true, "configHash": "", "summary": pluginCompileSummary(emptyPluginState()),
		}}
	}
	next, err := compilePluginState(ctx, request, nil)
	if err != nil {
		return map[string]any{"response": map[string]any{"accepted": false, "error": err.Error()}}
	}
	return map[string]any{"response": map[string]any{
		"accepted":          true,
		"configHash":        next.ConfigHash,
		"summary":           pluginCompileSummary(next),
		"domainResolutions": next.DomainResolutions,
	}}
}

func compilePluginState(ctx context.Context, request PluginSyncRequest, previous *state.PluginState) (state.PluginState, error) {
	next := emptyPluginState()
	now := time.Now().UTC()
	next.LastAttemptAt = &now
	if request.Plugin == nil {
		return next, nil
	}
	next.ConfigHash = request.ConfigHash
	if next.ConfigHash == "" {
		next.ConfigHash = state.ConfigHash(request.Plugin.Config)
	}
	next.ActivePlugin = &state.PluginMeta{UUID: request.Plugin.UUID, Name: request.Plugin.Name}
	sharedLists := readSharedLists(request.Plugin.Config)
	if err := validateSharedListReferences(request.Plugin.Config, sharedLists); err != nil {
		return next, err
	}
	configureConnectionDrop(&next, request.Plugin.Config, sharedLists)
	configureTorrentBlocker(&next, request.Plugin.Config, sharedLists)
	configureIngressFilter(&next, request.Plugin.Config, sharedLists)
	configureEgressFilter(&next, request.Plugin.Config, sharedLists)
	if err := resolveEgressDomains(ctx, &next, previous); err != nil {
		return next, err
	}
	return next, nil
}

func pluginCompileSummary(plugin state.PluginState) map[string]any {
	return map[string]any{
		"connectionDropWhitelistIps": len(plugin.ConnectionDropWhitelist),
		"ingressBlockedIps":          len(plugin.IngressBlocked),
		"egressBlockedIps":           len(plugin.EgressBlockedIPs),
		"egressBlockedDomains":       len(plugin.EgressBlockedDomains),
		"egressBlockedPorts":         len(plugin.EgressBlockedPorts),
		"torrentBlockerEnabled":      plugin.TorrentEnabled,
	}
}

func (m *Manager) CollectReports() map[string]any {
	reports := m.state.FlushTorrentReports()
	items := make([]map[string]any, 0, len(reports))
	for _, report := range reports {
		items = append(items, map[string]any{
			"actionReport": report.ActionReport,
			"coreReport":   report.CoreReport,
		})
	}
	return map[string]any{"response": map[string]any{"reports": items}}
}

func (m *Manager) BlockIPs(ctx context.Context, request BlockIPsRequest) map[string]any {
	for _, item := range request.IPs {
		if err := m.blockIPWithTimeout(ctx, item.IP, item.Timeout); err != nil {
			return map[string]any{"response": map[string]any{"accepted": false}}
		}
	}
	return map[string]any{"response": map[string]any{"accepted": true}}
}

func (m *Manager) UnblockIPs(ctx context.Context, request UnblockIPsRequest) map[string]any {
	for _, ip := range request.IPs {
		m.state.DeleteBlockedIP(ip)
		if m.nftReady {
			family, valid := nftSetFamily(ip)
			if !valid {
				return map[string]any{"response": map[string]any{"accepted": false}}
			}
			if err := m.nftDeleteElement(ctx, "torrent-blocker"+family, ip); err != nil {
				return map[string]any{"response": map[string]any{"accepted": false}}
			}
			if err := m.nftDeleteElement(ctx, "ingress-filter-ip"+family, ip); err != nil {
				return map[string]any{"response": map[string]any{"accepted": false}}
			}
		}
	}
	return map[string]any{"response": map[string]any{"accepted": true}}
}

func (m *Manager) RecreateTables(ctx context.Context) map[string]any {
	if err := m.recreateNFTables(ctx); err != nil {
		return map[string]any{"response": map[string]any{"accepted": false}}
	}
	return map[string]any{"response": map[string]any{"accepted": true}}
}

func (m *Manager) HandleWebhook(ctx context.Context, body any) {
	payload, ok := body.(map[string]any)
	if !ok {
		return
	}

	userID := stringValue(payload["email"])
	source := stringValue(payload["source"])
	ip := extractIP(source)
	if userID != "" && ip != "" {
		m.state.RecordUserIP(userID, ip, time.Now())
	}

	pluginState := m.state.PluginState()
	if !pluginState.TorrentEnabled || ip == "" || userID == "" {
		return
	}
	if isIgnoredIP(ip, pluginState.ConnectionDropWhitelist) || isIgnoredIP(ip, pluginState.TorrentIgnoredIPs) {
		return
	}
	if _, ignored := pluginState.TorrentIgnoredUsers[userID]; ignored {
		return
	}

	blocked := true
	if err := m.blockIPWithTimeout(ctx, ip, pluginState.TorrentDuration); err != nil {
		blocked = false
	}
	report := state.TorrentReport{
		ActionReport: map[string]any{
			"blocked":       blocked,
			"ip":            ip,
			"blockDuration": pluginState.TorrentDuration,
			"willUnblockAt": time.Now().Add(time.Duration(pluginState.TorrentDuration) * time.Second),
			"userId":        userID,
			"processedAt":   time.Now(),
		},
		CoreReport: payload,
	}
	m.state.AddTorrentReport(report)
}

func (m *Manager) restartCurrentCore(ctx context.Context) error {
	m.state.MarkHashesDirty()
	if m.state.RunningCoreType() == state.CoreTypeSingBox {
		return m.restartSingBox(ctx, m.state.SingBoxConfig())
	}
	return nil
}

func (m *Manager) restartSingBox(ctx context.Context, config map[string]any) error {
	config = applySingBoxAPIConfig(cloneMap(config), m.cfg)
	configPath := m.cfg.SingBoxConfigPath
	if configPath == "" {
		configPath = "/run/remnawave/sing-box.json"
	}
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return fmt.Errorf("create sing-box configuration directory: %w", err)
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("encode sing-box configuration: %w", err)
	}
	attemptedAt := time.Now().UTC()
	requestedHash := hashConfigBytes(encoded)
	m.singBoxApplyResult = newSingBoxApplyResult("PENDING", requestedHash, "", attemptedAt, nil, "NOT_REQUIRED")

	candidatePath, err := writeCandidateFile(configPath, encoded)
	if err != nil {
		m.singBoxApplyResult = newSingBoxApplyResult("FAILED", requestedHash, "", attemptedAt, nil, "NOT_REQUIRED")
		return fmt.Errorf("write sing-box candidate configuration: %w", err)
	}
	candidateOwned := true
	defer func() {
		if candidateOwned {
			_ = os.Remove(candidatePath)
		}
	}()

	previousCore := m.state.RunningCoreType()
	previousConfig, hadPreviousConfig, err := readOptionalFile(configPath)
	if err != nil {
		m.singBoxApplyResult = newSingBoxApplyResult("FAILED", requestedHash, "", attemptedAt, nil, "NOT_REQUIRED")
		return fmt.Errorf("read current sing-box configuration: %w", err)
	}
	previousRuntimeConfig := m.state.SingBoxConfig()
	if previousCore == state.CoreTypeSingBox && hadPreviousConfig {
		if err := json.Unmarshal(previousConfig, &previousRuntimeConfig); err != nil {
			m.singBoxApplyResult = newSingBoxApplyResult("FAILED", requestedHash, "", attemptedAt, nil, "NOT_REQUIRED")
			return fmt.Errorf("decode current sing-box configuration for rollback: %w", err)
		}
	}
	previousHash := ""
	if hadPreviousConfig {
		previousHash = hashConfigBytes(previousConfig)
	}
	lastGoodPath := m.singBoxLastGoodPath(configPath)

	if err := m.checkSingBoxConfig(ctx, candidatePath); err != nil {
		if previousCore == state.CoreTypeSingBox && hadPreviousConfig {
			m.state.SetSingBoxConfig(previousRuntimeConfig)
		}
		m.singBoxApplyResult = newSingBoxApplyResult("REJECTED", requestedHash, previousHash, attemptedAt, nil, "NOT_REQUIRED")
		return err
	}

	if previousCore == state.CoreTypeSingBox && hadPreviousConfig {
		if err := writeFileAtomic(lastGoodPath, previousConfig, 0o600); err != nil {
			m.singBoxApplyResult = newSingBoxApplyResult("FAILED", requestedHash, previousHash, attemptedAt, nil, "NOT_REQUIRED")
			return fmt.Errorf("save current sing-box configuration as last-known-good: %w", err)
		}
	}

	if err := os.Chmod(candidatePath, 0o644); err != nil {
		m.singBoxApplyResult = newSingBoxApplyResult("FAILED", requestedHash, previousHash, attemptedAt, nil, "NOT_REQUIRED")
		return fmt.Errorf("set sing-box candidate permissions: %w", err)
	}
	if err := os.Rename(candidatePath, configPath); err != nil {
		m.singBoxApplyResult = newSingBoxApplyResult("FAILED", requestedHash, previousHash, attemptedAt, nil, "NOT_REQUIRED")
		return fmt.Errorf("activate sing-box candidate configuration: %w", err)
	}
	candidateOwned = false
	if err := syncDirectory(configDir); err != nil {
		restoreErr := restoreOptionalFile(configPath, previousConfig, hadPreviousConfig, 0o644)
		if restoreErr != nil {
			m.singBoxApplyResult = newSingBoxApplyResult("FAILED", requestedHash, previousHash, attemptedAt, nil, "FAILED")
			return fmt.Errorf("sync sing-box configuration directory: %w; restore current configuration: %v", err, restoreErr)
		}
		m.singBoxApplyResult = newSingBoxApplyResult("FAILED", requestedHash, previousHash, attemptedAt, nil, "SUCCEEDED")
		return fmt.Errorf("sync sing-box configuration directory: %w", err)
	}

	_ = m.supervisor.StopProcess(ctx, singBoxProcessName)
	if err := m.supervisor.StartProcess(ctx, singBoxProcessName); err != nil {
		return m.failSingBoxActivation(ctx, fmt.Errorf("start sing-box: %w", err), requestedHash, previousHash, attemptedAt, previousCore, previousRuntimeConfig, previousConfig, hadPreviousConfig, configPath, lastGoodPath)
	}
	if err := m.waitForSingBoxHealthy(ctx); err != nil {
		return m.failSingBoxActivation(ctx, err, requestedHash, previousHash, attemptedAt, previousCore, previousRuntimeConfig, previousConfig, hadPreviousConfig, configPath, lastGoodPath)
	}
	if err := writeFileAtomic(lastGoodPath, encoded, 0o600); err != nil {
		return m.failSingBoxActivation(ctx, fmt.Errorf("persist sing-box last-known-good configuration: %w", err), requestedHash, previousHash, attemptedAt, previousCore, previousRuntimeConfig, previousConfig, hadPreviousConfig, configPath, lastGoodPath)
	}
	appliedAt := time.Now().UTC()
	m.singBoxApplyResult = newSingBoxApplyResult("APPLIED", requestedHash, requestedHash, attemptedAt, &appliedAt, "NOT_REQUIRED")
	m.state.SetSingBoxConfig(config)
	m.state.SetRunningCore(state.CoreTypeSingBox)
	m.refreshOnlineStatus(ctx)
	return nil
}

func (m *Manager) checkSingBoxConfig(ctx context.Context, path string) error {
	binary := m.cfg.SingBoxBinaryPath
	if binary == "" {
		binary = "/usr/local/bin/sing-box"
	}
	runner := m.runCommand
	if runner == nil {
		runner = runCombinedOutput
	}
	output, err := runner(ctx, binary, "check", "-c", path)
	if err == nil {
		return nil
	}
	message := strings.TrimSpace(string(output))
	if len(message) > 2048 {
		message = message[:2048] + "..."
	}
	if message == "" {
		return fmt.Errorf("sing-box configuration preflight failed: %w", err)
	}
	return fmt.Errorf("sing-box configuration preflight failed: %w: %s", err, message)
}

func (m *Manager) waitForSingBoxHealthy(ctx context.Context) error {
	timeout := m.healthTimeout
	if timeout <= 0 {
		timeout = defaultSingBoxHealthTimeout
	}
	interval := m.healthPollInterval
	if interval <= 0 {
		interval = defaultSingBoxHealthPollInterval
	}
	healthCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	var lastErr error
	for {
		info, err := m.supervisor.GetProcessInfo(healthCtx, singBoxProcessName)
		if err != nil {
			lastErr = fmt.Errorf("query supervisord: %w", err)
		} else if info.State == supervisor.StateRunning {
			if m.singStats == nil {
				lastErr = errors.New("sing-box internal statistics API client is unavailable")
			} else if _, err := m.singStats.System(healthCtx); err != nil {
				lastErr = fmt.Errorf("sing-box internal statistics API is unavailable: %w", err)
			} else {
				return nil
			}
		} else {
			lastErr = fmt.Errorf("supervisord reports sing-box state %s (%d): %s", info.StateName, info.State, info.Raw)
			if info.State == supervisor.StateFatal || info.State == supervisor.StateExited || info.State == supervisor.StateStopped {
				return fmt.Errorf("sing-box failed health confirmation: %w", lastErr)
			}
		}

		timer := time.NewTimer(interval)
		select {
		case <-healthCtx.Done():
			timer.Stop()
			if lastErr == nil {
				lastErr = healthCtx.Err()
			}
			return fmt.Errorf("sing-box failed health confirmation: %w", lastErr)
		case <-timer.C:
		}
	}
}

func (m *Manager) failSingBoxActivation(ctx context.Context, activationErr error, requestedHash, previousHash string, attemptedAt time.Time, previousCore state.CoreType, previousRuntimeConfig map[string]any, previousConfig []byte, hadPreviousConfig bool, configPath, lastGoodPath string) error {
	rollbackErr := m.rollbackSingBox(ctx, previousCore, previousRuntimeConfig, previousConfig, hadPreviousConfig, configPath, lastGoodPath)
	if rollbackErr != nil {
		m.singBoxApplyResult = newSingBoxApplyResult("FAILED", requestedHash, previousHash, attemptedAt, nil, "FAILED")
		return fmt.Errorf("%w; rollback failed: %v", activationErr, rollbackErr)
	}
	if previousCore == "" && !hadPreviousConfig {
		m.singBoxApplyResult = newSingBoxApplyResult("FAILED", requestedHash, "", attemptedAt, nil, "NOT_AVAILABLE")
		return fmt.Errorf("%w; first activation failed and no previous configuration or core was available", activationErr)
	}
	rolledBackAt := time.Now().UTC()
	m.singBoxApplyResult = newSingBoxApplyResult("ROLLED_BACK", requestedHash, previousHash, attemptedAt, &rolledBackAt, "SUCCEEDED")
	return fmt.Errorf("%w; previous configuration and core restored", activationErr)
}

func (m *Manager) rollbackSingBox(ctx context.Context, previousCore state.CoreType, previousRuntimeConfig map[string]any, previousConfig []byte, hadPreviousConfig bool, configPath, lastGoodPath string) error {
	_ = m.supervisor.StopProcess(ctx, singBoxProcessName)

	restoreErr := restoreOptionalFile(configPath, previousConfig, hadPreviousConfig, 0o644)
	if !hadPreviousConfig {
		lastGood, exists, err := readOptionalFile(lastGoodPath)
		if err != nil {
			restoreErr = err
		} else if previousCore == state.CoreTypeSingBox && exists {
			restoreErr = writeFileAtomic(configPath, lastGood, 0o644)
		}
	}
	if restoreErr == nil && previousCore == state.CoreTypeSingBox && hadPreviousConfig {
		restoreErr = writeFileAtomic(lastGoodPath, previousConfig, 0o600)
	}
	if restoreErr != nil {
		m.state.SetRunningCore("")
		m.refreshOnlineStatus(ctx)
		return fmt.Errorf("restore sing-box configuration: %w", restoreErr)
	}

	var startErr error
	switch previousCore {
	case state.CoreTypeSingBox:
		m.state.SetSingBoxConfig(previousRuntimeConfig)
		startErr = m.supervisor.StartProcess(ctx, singBoxProcessName)
	}
	if startErr != nil {
		m.state.SetRunningCore("")
		m.refreshOnlineStatus(ctx)
		return fmt.Errorf("restart previous %s core: %w", previousCore, startErr)
	}
	m.state.SetRunningCore(previousCore)
	m.refreshOnlineStatus(ctx)
	return nil
}

func (m *Manager) singBoxLastGoodPath(configPath string) string {
	if m.cfg.SingBoxLastGoodPath != "" {
		return m.cfg.SingBoxLastGoodPath
	}
	return configPath + ".last-good"
}

func (m *Manager) recordUnchangedSingBoxConfig(config map[string]any) {
	encoded, err := json.Marshal(config)
	if err != nil {
		m.singBoxApplyResult = nil
		return
	}
	now := time.Now().UTC()
	hash := hashConfigBytes(encoded)
	m.singBoxApplyResult = newSingBoxApplyResult("UNCHANGED", hash, hash, now, nil, "NOT_REQUIRED")
}

func (m *Manager) startConfigApplyResult(coreType state.CoreType) map[string]any {
	if coreType != state.CoreTypeSingBox || m.singBoxApplyResult == nil {
		return nil
	}
	return cloneMap(m.singBoxApplyResult)
}

func newSingBoxApplyResult(status, requestedHash, activeHash string, attemptedAt time.Time, appliedAt *time.Time, rollback string) map[string]any {
	result := map[string]any{
		"status":        status,
		"requestedHash": requestedHash,
		"activeHash":    nil,
		"attemptedAt":   attemptedAt.Format(time.RFC3339Nano),
		"appliedAt":     nil,
		"rollback":      rollback,
	}
	if activeHash != "" {
		result["activeHash"] = activeHash
	}
	if appliedAt != nil {
		result["appliedAt"] = appliedAt.Format(time.RFC3339Nano)
	}
	return result
}

func hashConfigBytes(data []byte) string {
	var decoded any
	if err := json.Unmarshal(data, &decoded); err == nil {
		if canonical, err := json.Marshal(decoded); err == nil {
			data = canonical
		}
	}
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func writeCandidateFile(targetPath string, data []byte) (string, error) {
	dir := filepath.Dir(targetPath)
	file, err := os.CreateTemp(dir, "."+filepath.Base(targetPath)+".candidate-*")
	if err != nil {
		return "", err
	}
	path := file.Name()
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		return "", err
	}
	if _, err := file.Write(data); err != nil {
		return "", err
	}
	if err := file.Sync(); err != nil {
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	remove = false
	return path, nil
}

func writeFileAtomic(targetPath string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o755); err != nil {
		return err
	}
	temporaryPath, err := writeCandidateFile(targetPath, data)
	if err != nil {
		return err
	}
	defer os.Remove(temporaryPath)
	if err := os.Chmod(temporaryPath, mode); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, targetPath); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(targetPath))
}

func readOptionalFile(path string) ([]byte, bool, error) {
	data, err := os.ReadFile(path)
	if err == nil {
		return data, true, nil
	}
	if os.IsNotExist(err) {
		return nil, false, nil
	}
	return nil, false, err
}

func restoreOptionalFile(path string, data []byte, exists bool, mode os.FileMode) error {
	if exists {
		return writeFileAtomic(path, data, mode)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (m *Manager) refreshOnlineStatus(ctx context.Context) {
	singBoxInfo, _ := m.supervisor.GetProcessInfo(ctx, singBoxProcessName)
	m.state.SetOnlineStatus(singBoxInfo.State == supervisor.StateRunning)
}

func (m *Manager) activeVersion(coreType state.CoreType) *string {
	if coreType == state.CoreTypeSingBox {
		return m.state.CoreVersion()
	}
	return nil
}

func (m *Manager) coreVersions() map[string]any {
	return map[string]any{
		"singBox": derefString(m.state.CoreVersion()),
	}
}

func (m *Manager) readVersion(ctx context.Context, binary string, args ...string) *string {
	if !commandExists(binary) {
		return nil
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) == 0 || lines[0] == "" {
		return nil
	}
	version := formatCoreVersion(binary, lines[0])
	return &version
}

func formatCoreVersion(binary, line string) string {
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) == 0 {
		return ""
	}

	name := filepath.Base(binary)
	switch name {
	case "sing-box":
		if len(fields) >= 3 && strings.EqualFold(fields[0], "sing-box") && strings.EqualFold(fields[1], "version") {
			version := trimVersionPrefix(fields[2])
			if version == "unknown" {
				if fallback := trimVersionPrefix(os.Getenv("SING_BOX_VERSION")); fallback != "" {
					return fallback
				}
			}
			return version
		}
	}

	return strings.TrimSpace(line)
}

func trimVersionPrefix(value string) string {
	value = strings.TrimSpace(value)
	return strings.TrimPrefix(value, "v")
}

func (m *Manager) applyAddUserRequest(request AddUserRequest) error {
	seen := map[string]struct{}{}
	for _, item := range request.Data {
		if _, exists := seen[item.Username]; !exists {
			if err := m.removeUserEverywhere(item.Username); err != nil {
				return err
			}
			seen[item.Username] = struct{}{}
		}
		if err := m.addUserToTag(item); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) statUsernamesForUser(username string) []string {
	values := []string{username}
	seen := map[string]struct{}{username: {}}
	for tag, users := range m.state.InboundUsersMap() {
		for _, user := range users {
			if user.UserID != username {
				continue
			}
			statsUsername := statname.UserInbound(username, tag)
			if _, ok := seen[statsUsername]; ok {
				continue
			}
			values = append(values, statsUsername)
			seen[statsUsername] = struct{}{}
		}
	}
	return values
}

func (m *Manager) applyAddUsersRequest(request AddUsersRequest) error {
	for _, user := range request.Users {
		if err := m.removeUserEverywhere(user.UserData.UserID); err != nil {
			return err
		}
		for _, inbound := range user.InboundData {
			item := AddUserItem{
				Type:     inbound.Type,
				Tag:      inbound.Tag,
				Username: user.UserData.UserID,
				Password: user.UserData.TrojanPassword,
				UUID:     user.UserData.VLESSUUID,
				Flow:     inbound.Flow,
			}
			if inbound.Type == "shadowsocks" || inbound.Type == "shadowsocks22" {
				item.Password = user.UserData.SSPassword
			}
			if inbound.Type == "hysteria" {
				item.Password = user.UserData.VLESSUUID
			}
			if err := m.addUserToTag(item); err != nil {
				return err
			}
		}
	}
	return nil
}

func (m *Manager) addUserToTag(item AddUserItem) error {
	switch m.state.RunningCoreType() {
	case state.CoreTypeSingBox:
		config := m.state.SingBoxConfig()
		if err := addSingBoxUser(config, item); err != nil {
			return err
		}
		m.state.SetSingBoxConfig(config)
	case "":
		return errors.New("sing-box core is not running")
	}
	return nil
}

func (m *Manager) removeUserEverywhere(username string) error {
	switch m.state.RunningCoreType() {
	case state.CoreTypeSingBox:
		config := m.state.SingBoxConfig()
		removeSingBoxUser(config, username)
		m.state.SetSingBoxConfig(config)
	case "":
		return errors.New("sing-box core is not running")
	}
	return nil
}

func (m *Manager) recreateNFTables(ctx context.Context) error {
	if !m.nftReady {
		return nil
	}
	_ = m.runNft(ctx, "delete", "table", "inet", nftTableName)
	if err := m.runNft(ctx, "add", "table", "inet", nftTableName); err != nil {
		return err
	}
	for _, cmd := range [][]string{
		{"add", "set", "inet", nftTableName, "torrent-blocker", "{", "type", "ipv4_addr;", "flags", "timeout;", "}"},
		{"add", "set", "inet", nftTableName, "torrent-blocker6", "{", "type", "ipv6_addr;", "flags", "timeout;", "}"},
		{"add", "set", "inet", nftTableName, "ingress-filter-ip", "{", "type", "ipv4_addr;", "flags", "interval;", "auto-merge;", "}"},
		{"add", "set", "inet", nftTableName, "ingress-filter-ip6", "{", "type", "ipv6_addr;", "flags", "interval;", "auto-merge;", "}"},
		{"add", "set", "inet", nftTableName, "egress-filter-ip", "{", "type", "ipv4_addr;", "flags", "interval;", "auto-merge;", "}"},
		{"add", "set", "inet", nftTableName, "egress-filter-ip6", "{", "type", "ipv6_addr;", "flags", "interval;", "auto-merge;", "}"},
		{"add", "set", "inet", nftTableName, "egress-filter-port", "{", "type", "inet_service;", "}"},
		{"add", "chain", "inet", nftTableName, "input", "{", "type", "filter", "hook", "input", "priority", "0;", "policy", "accept;", "}"},
		{"add", "chain", "inet", nftTableName, "output", "{", "type", "filter", "hook", "output", "priority", "0;", "policy", "accept;", "}"},
		{"add", "rule", "inet", nftTableName, "input", "ip", "saddr", "@ingress-filter-ip", "drop"},
		{"add", "rule", "inet", nftTableName, "input", "ip", "saddr", "@torrent-blocker", "drop"},
		{"add", "rule", "inet", nftTableName, "input", "ip6", "saddr", "@ingress-filter-ip6", "drop"},
		{"add", "rule", "inet", nftTableName, "input", "ip6", "saddr", "@torrent-blocker6", "drop"},
		{"add", "rule", "inet", nftTableName, "output", "ip", "daddr", "@egress-filter-ip", "drop"},
		{"add", "rule", "inet", nftTableName, "output", "ip6", "daddr", "@egress-filter-ip6", "drop"},
		{"add", "rule", "inet", nftTableName, "output", "tcp", "dport", "@egress-filter-port", "drop"},
		{"add", "rule", "inet", nftTableName, "output", "udp", "dport", "@egress-filter-port", "drop"},
	} {
		if err := m.runNft(ctx, cmd...); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) syncNFTState(ctx context.Context, pluginState state.PluginState) error {
	if !m.nftReady {
		return nil
	}
	if err := m.nftSyncSet(ctx, "ingress-filter-ip", pluginState.IngressBlocked, false); err != nil {
		return err
	}
	if err := m.nftSyncSet(ctx, "ingress-filter-ip6", pluginState.IngressBlocked, true); err != nil {
		return err
	}
	if err := m.nftSyncSet(ctx, "egress-filter-ip", pluginState.EgressBlockedIPs, false); err != nil {
		return err
	}
	if err := m.nftSyncSet(ctx, "egress-filter-ip6", pluginState.EgressBlockedIPs, true); err != nil {
		return err
	}
	if err := m.nftSyncPortSet(ctx, "egress-filter-port", pluginState.EgressBlockedPorts); err != nil {
		return err
	}
	return nil
}

func (m *Manager) applyPluginNFTState(ctx context.Context, next, fallback state.PluginState) error {
	if err := m.recreateNFTables(ctx); err != nil {
		m.restorePluginNFTState(fallback)
		return err
	}
	if err := m.syncNFTState(ctx, next); err != nil {
		m.restorePluginNFTState(fallback)
		return err
	}
	return nil
}

func (m *Manager) restorePluginNFTState(pluginState state.PluginState) {
	if !m.nftReady {
		return
	}
	rollbackCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := m.recreateNFTables(rollbackCtx); err != nil {
		m.logger.Error("failed to recreate nftables during plugin rollback", "error", err)
		return
	}
	if err := m.syncNFTState(rollbackCtx, pluginState); err != nil {
		m.logger.Error("failed to restore last-good plugin nftables rules", "error", err)
	}
}

func (m *Manager) blockIPWithTimeout(ctx context.Context, ip string, timeout int) error {
	family, valid := nftSetFamily(ip)
	if !valid {
		return fmt.Errorf("invalid IP address %q", ip)
	}
	until := time.Time{}
	if timeout > 0 {
		until = time.Now().Add(time.Duration(timeout) * time.Second)
	}
	m.state.SetBlockedIP(ip, until)
	if m.nftReady {
		args := []string{"add", "element", "inet", nftTableName, "torrent-blocker" + family, "{", ip}
		if timeout > 0 {
			args = append(args, "timeout", fmt.Sprintf("%ds", timeout))
		}
		args = append(args, "}")
		if err := m.runNft(ctx, args...); err != nil {
			return err
		}
	}
	m.dropConnections(ip)
	return nil
}

func (m *Manager) nftSyncSet(ctx context.Context, setName string, items []string, ipv6 bool) error {
	if err := m.runNft(ctx, "flush", "set", "inet", nftTableName, setName); err != nil {
		return err
	}
	filtered := make([]string, 0, len(items))
	for _, item := range items {
		value, itemIPv6, valid := normalizeIPOrCIDR(item)
		if !valid || itemIPv6 != ipv6 {
			continue
		}
		filtered = append(filtered, value)
	}
	if len(filtered) == 0 {
		return nil
	}
	args := []string{"add", "element", "inet", nftTableName, setName, "{", strings.Join(filtered, ", "), "}"}
	return m.runNft(ctx, args...)
}

func normalizeIPOrCIDR(value string) (string, bool, bool) {
	value = strings.TrimSpace(value)
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), ip.To4() == nil, true
	}
	ip, network, err := net.ParseCIDR(value)
	if err != nil {
		return "", false, false
	}
	network.IP = ip.Mask(network.Mask)
	return network.String(), ip.To4() == nil, true
}

func nftSetFamily(ip string) (string, bool) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", false
	}
	if parsed.To4() == nil {
		return "6", true
	}
	return "", true
}

func (m *Manager) nftSyncPortSet(ctx context.Context, setName string, ports []int) error {
	if err := m.runNft(ctx, "flush", "set", "inet", nftTableName, setName); err != nil {
		return err
	}
	if len(ports) == 0 {
		return nil
	}
	values := make([]string, 0, len(ports))
	for _, port := range ports {
		values = append(values, strconv.Itoa(port))
	}
	args := []string{"add", "element", "inet", nftTableName, setName, "{", strings.Join(values, ", "), "}"}
	return m.runNft(ctx, args...)
}

func (m *Manager) nftDeleteElement(ctx context.Context, setName, value string) error {
	if !m.nftReady {
		return nil
	}
	return m.runNft(ctx, "delete", "element", "inet", nftTableName, setName, "{", value, "}")
}

func (m *Manager) runNft(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, "nft", args...)
	output, err := cmd.CombinedOutput()
	if err != nil && len(output) > 0 && strings.Contains(string(output), "No such file or directory") {
		return nil
	}
	if err != nil {
		return fmt.Errorf("nft %s failed: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func (m *Manager) dropConnections(ip string) {
	if ip == "" || isIgnoredIP(ip, nil) || !commandExists("ss") {
		return
	}
	_, _ = exec.Command("ss", "-K", "dst", ip).CombinedOutput()
	_, _ = exec.Command("ss", "-K", "src", ip).CombinedOutput()
}

func applySingBoxAPIConfig(config map[string]any, cfg config.Config) map[string]any {
	if len(config) == 0 || cfg.SingBoxAPIPort <= 0 {
		return config
	}
	encodeSingBoxConfigUsers(config)

	experimental := ensureMap(config, "experimental")
	statsInbounds := []string{}
	statsOutbounds := []string{}
	statsUsers := []string{}
	for _, inbound := range asMapSlice(config["inbounds"]) {
		if tag := stringValue(inbound["tag"]); tag != "" {
			statsInbounds = append(statsInbounds, tag)
		}
		for _, user := range asMapSlice(inbound["users"]) {
			if name := firstNonEmpty(stringValue(user["name"]), stringValue(user["email"])); name != "" {
				statsUsers = append(statsUsers, name)
			}
		}
	}
	for _, outbound := range asMapSlice(config["outbounds"]) {
		if tag := stringValue(outbound["tag"]); tag != "" {
			statsOutbounds = append(statsOutbounds, tag)
		}
	}
	experimental["v2ray_api"] = map[string]any{
		"listen": fmt.Sprintf("127.0.0.1:%d", singBoxV2RayAPIPort(cfg)),
		"stats": map[string]any{
			"enabled":   true,
			"inbounds":  toAnyStringSlice(statsInbounds),
			"outbounds": toAnyStringSlice(statsOutbounds),
			"users":     toAnyStringSlice(statsUsers),
		},
	}
	clashAPI := ensureMap(experimental, "clash_api")
	clashAPI["external_controller"] = fmt.Sprintf("127.0.0.1:%d", cfg.SingBoxAPIPort)
	if cfg.InternalRESTToken != "" {
		clashAPI["secret"] = cfg.InternalRESTToken
	} else {
		delete(clashAPI, "secret")
	}
	experimental["clash_api"] = clashAPI
	config["experimental"] = experimental
	return config
}

func encodeSingBoxConfigUsers(config map[string]any) {
	for _, inbound := range asMapSlice(config["inbounds"]) {
		tag := stringValue(inbound["tag"])
		if tag == "" {
			continue
		}
		users := asMapSlice(inbound["users"])
		for _, user := range users {
			userID := statname.UserID(firstNonEmpty(stringValue(user["name"]), stringValue(user["email"])))
			if userID == "" {
				continue
			}
			user["name"] = statname.UserInbound(userID, tag)
		}
		inbound["users"] = toAnySlice(users)
	}
}

func singBoxV2RayAPIPort(cfg config.Config) int {
	if cfg.SingBoxV2RayAPIPort > 0 {
		return cfg.SingBoxV2RayAPIPort
	}
	return cfg.SingBoxAPIPort + 1
}

func addSingBoxUser(config map[string]any, item AddUserItem) error {
	for _, inbound := range asMapSlice(config["inbounds"]) {
		if stringValue(inbound["tag"]) != item.Tag {
			continue
		}
		protocol := normalizeSingBoxType(stringValue(inbound["type"]))
		users := ensureSliceMap(inbound, "users")
		user := map[string]any{"name": statname.UserInbound(item.Username, item.Tag)}
		switch protocol {
		case "anytls":
			user["password"] = item.Password
		case "hysteria2":
			user["password"] = item.Password
		case "tuic":
			user["uuid"] = item.UUID
			user["password"] = item.Password
		case "trojan", "shadowtls", "shadowsocks":
			user["password"] = item.Password
		case "vless", "vmess":
			user["uuid"] = item.UUID
		default:
			return fmt.Errorf("sing-box protocol %s is not supported", protocol)
		}
		users = append(users, user)
		inbound["users"] = toAnySlice(users)
		return nil
	}
	return fmt.Errorf("inbound %s not found", item.Tag)
}

func removeSingBoxUser(config map[string]any, username string) {
	for _, inbound := range asMapSlice(config["inbounds"]) {
		users := asMapSlice(inbound["users"])
		filtered := make([]map[string]any, 0, len(users))
		for _, user := range users {
			if statname.UserID(firstNonEmpty(stringValue(user["name"]), stringValue(user["email"]))) == username {
				continue
			}
			filtered = append(filtered, user)
		}
		inbound["users"] = toAnySlice(filtered)
	}
}

type pluginSharedList struct {
	Type  string
	Items []string
}

func readSharedLists(config map[string]any) map[string]pluginSharedList {
	out := map[string]pluginSharedList{}
	for _, list := range asMapSlice(config["sharedLists"]) {
		name := stringValue(list["name"])
		listType := stringValue(list["type"])
		if name == "" || listType == "" {
			continue
		}
		items := make([]string, 0)
		for _, item := range asAnySlice(list["items"]) {
			switch value := item.(type) {
			case string:
				items = append(items, value)
			case float64:
				if value == float64(int(value)) {
					items = append(items, strconv.Itoa(int(value)))
				}
			}
		}
		out[name] = pluginSharedList{Type: listType, Items: items}
	}
	return out
}

func validateSharedListReferences(config map[string]any, shared map[string]pluginSharedList) error {
	type referenceField struct {
		values   []any
		expected string
	}
	torrent := ensureConfigMap(config["torrentBlocker"])
	connectionDrop := ensureConfigMap(config["connectionDrop"])
	ingress := ensureConfigMap(config["ingressFilter"])
	egress := ensureConfigMap(config["egressFilter"])
	fields := []referenceField{
		{values: asAnySlice(ensureConfigMap(torrent["ignoreLists"])["ip"]), expected: "ipList"},
		{values: asAnySlice(connectionDrop["whitelistIps"]), expected: "ipList"},
		{values: asAnySlice(ingress["blockedIps"]), expected: "ipList"},
		{values: asAnySlice(egress["blockedIps"]), expected: "ipList"},
		{values: asAnySlice(egress["blockedDomains"]), expected: "domainList"},
		{values: asAnySlice(egress["blockedPorts"]), expected: "portList"},
	}
	for _, field := range fields {
		for _, item := range field.values {
			value, ok := item.(string)
			if !ok || !strings.HasPrefix(value, "ext:") {
				continue
			}
			list, exists := shared[value]
			if !exists {
				return fmt.Errorf("shared list %q was not provided", value)
			}
			if list.Type != field.expected {
				return fmt.Errorf("shared list %q has type %q, expected %q", value, list.Type, field.expected)
			}
		}
	}
	return nil
}

func configureConnectionDrop(target *state.PluginState, config map[string]any, shared map[string]pluginSharedList) {
	plugin := ensureConfigMap(config["connectionDrop"])
	if !boolValue(plugin["enabled"]) {
		return
	}
	target.ConnectionDropWhitelist = sliceToSet(resolveIPList(stringSlice(plugin["whitelistIps"]), shared))
}

func configureTorrentBlocker(target *state.PluginState, config map[string]any, shared map[string]pluginSharedList) {
	plugin := ensureConfigMap(config["torrentBlocker"])
	if !boolValue(plugin["enabled"]) {
		return
	}
	target.TorrentEnabled = true
	target.TorrentDuration = intValue(plugin["blockDuration"])
	ignoreLists := ensureConfigMap(plugin["ignoreLists"])
	target.TorrentIgnoredIPs = sliceToSet(resolveIPList(stringSlice(ignoreLists["ip"]), shared))
	target.TorrentIgnoredUsers = sliceToSet(numberStrings(ignoreLists["userId"]))
	target.TorrentIncludeRuleTags = sliceToSet(stringSlice(plugin["includeRuleTags"]))
}

func configureIngressFilter(target *state.PluginState, config map[string]any, shared map[string]pluginSharedList) {
	plugin := ensureConfigMap(config["ingressFilter"])
	if !boolValue(plugin["enabled"]) {
		return
	}
	target.IngressBlocked = resolveIPList(stringSlice(plugin["blockedIps"]), shared)
}

func configureEgressFilter(target *state.PluginState, config map[string]any, shared map[string]pluginSharedList) {
	plugin := ensureConfigMap(config["egressFilter"])
	if !boolValue(plugin["enabled"]) {
		return
	}
	target.EgressBlockedBaseIPs = resolveIPList(stringSlice(plugin["blockedIps"]), shared)
	target.EgressBlockedIPs = append([]string(nil), target.EgressBlockedBaseIPs...)
	target.EgressBlockedDomains = resolveStringList(stringSlice(plugin["blockedDomains"]), shared)
	target.EgressBlockedPorts = resolvePortList(asAnySlice(plugin["blockedPorts"]), shared)
}

func resolveEgressDomains(ctx context.Context, target *state.PluginState, previous *state.PluginState) error {
	resolved := append([]string(nil), target.EgressBlockedBaseIPs...)
	target.DomainResolutions = map[string]state.DomainResolution{}
	for _, domain := range target.EgressBlockedDomains {
		if net.ParseIP(domain) != nil || strings.ContainsAny(domain, " /\\") {
			return fmt.Errorf("invalid egress domain %q", domain)
		}
		now := time.Now().UTC()
		status := state.DomainResolution{Domain: domain, LastAttemptAt: &now, Addresses: []string{}}
		ips, err := net.DefaultResolver.LookupIP(ctx, "ip", domain)
		if err != nil {
			status.LastError = err.Error()
			status.FailureCount = 1
			status.Stale = true
			if previous != nil {
				if existing, ok := previous.DomainResolutions[domain]; ok && len(existing.Addresses) > 0 {
					status.Addresses = append([]string(nil), existing.Addresses...)
					status.LastSuccessAt = existing.LastSuccessAt
					status.FailureCount = existing.FailureCount + 1
					resolved = append(resolved, status.Addresses...)
					target.DomainResolutions[domain] = status
					continue
				}
			}
			return fmt.Errorf("resolve egress domain %q: %w", domain, err)
		}
		if len(ips) == 0 {
			return fmt.Errorf("egress domain %q resolved to no addresses", domain)
		}
		for _, ip := range ips {
			status.Addresses = append(status.Addresses, ip.String())
		}
		status.Addresses = uniqueStrings(status.Addresses)
		status.LastSuccessAt = &now
		resolved = append(resolved, status.Addresses...)
		target.DomainResolutions[domain] = status
	}
	target.EgressBlockedIPs = uniqueStrings(resolved)
	return nil
}

func emptyPluginState() state.PluginState {
	return state.PluginState{
		DomainResolutions:       map[string]state.DomainResolution{},
		ConnectionDropWhitelist: map[string]struct{}{},
		TorrentIgnoredIPs:       map[string]struct{}{},
		TorrentIgnoredUsers:     map[string]struct{}{},
		TorrentIncludeRuleTags:  map[string]struct{}{},
	}
}

func ptrTime(value time.Time) *time.Time { return &value }

func resolveIPList(values []string, shared map[string]pluginSharedList) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.HasPrefix(value, "ext:") {
			out = append(out, shared[value].Items...)
			continue
		}
		out = append(out, value)
	}
	return out
}

func resolveStringList(values []string, shared map[string]pluginSharedList) []string {
	return uniqueStrings(resolveIPList(values, shared))
}

func resolvePortList(values []any, shared map[string]pluginSharedList) []int {
	ports := make([]int, 0, len(values))
	appendValue := func(value string) {
		port, err := strconv.Atoi(value)
		if err == nil && port >= 1 && port <= 65535 {
			ports = append(ports, port)
		}
	}
	for _, item := range values {
		switch value := item.(type) {
		case float64:
			appendValue(strconv.Itoa(int(value)))
		case string:
			if strings.HasPrefix(value, "ext:") {
				for _, sharedValue := range shared[value].Items {
					appendValue(sharedValue)
				}
			} else {
				appendValue(value)
			}
		}
	}
	sort.Ints(ports)
	out := ports[:0]
	for _, port := range ports {
		if len(out) == 0 || out[len(out)-1] != port {
			out = append(out, port)
		}
	}
	return out
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func normalizeSingBoxKeys(value any) map[string]any {
	out := normalizeSingBoxValue(value)
	typed, _ := out.(map[string]any)
	return typed
}

func normalizeSingBoxValue(value any) any {
	switch typed := value.(type) {
	case []any:
		out := make([]any, 0, len(typed))
		for _, item := range typed {
			out = append(out, normalizeSingBoxValue(item))
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			mapped := singBoxKeyAliases[key]
			if mapped == "" {
				mapped = key
			}
			out[mapped] = normalizeSingBoxValue(item)
		}
		return out
	default:
		return value
	}
}

func normalizeSingBoxType(value string) string {
	if strings.EqualFold(value, "hy2") || strings.EqualFold(value, "hysteria2") {
		return "hysteria2"
	}
	return value
}

func wrapStartResponse(started bool, version *string, err *string, nodeVersion string, snapshot system.Snapshot, runningCore string, versions map[string]any, configApply map[string]any) map[string]any {
	response := map[string]any{
		"isStarted":    started,
		"version":      derefString(version),
		"runningCore":  runningCore,
		"coreVersions": versions,
		"error":        derefString(err),
		"nodeInformation": map[string]any{
			"version": nodeVersion,
		},
		"system": snapshot,
	}
	if configApply != nil {
		response["configApply"] = cloneMap(configApply)
	}
	return map[string]any{
		"response": response,
	}
}

func derefString(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func ptrString(value string) *string {
	return &value
}

func commandExists(name string) bool {
	if strings.ContainsRune(name, os.PathSeparator) {
		_, err := os.Stat(name)
		return err == nil
	}
	_, err := exec.LookPath(name)
	return err == nil
}

func hasNetAdmin() bool {
	payload, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(payload), "\n") {
		if !strings.HasPrefix(line, "CapEff:") {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
		return err == nil && value&(1<<12) != 0
	}
	return false
}

func extractIP(source string) string {
	if source == "" {
		return ""
	}
	value := strings.TrimPrefix(source, "tcp:")
	value = strings.TrimPrefix(value, "udp:")
	value = strings.Trim(value, "[]")
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return ""
}

func sameStringSet(left, right map[string]struct{}) bool {
	if len(left) != len(right) {
		return false
	}
	for key := range left {
		if _, ok := right[key]; !ok {
			return false
		}
	}
	return true
}

func isIgnoredIP(ip string, extra map[string]struct{}) bool {
	if _, ok := defaultIgnoredIPs[ip]; ok {
		return true
	}
	if extra == nil {
		return false
	}
	_, ok := extra[ip]
	return ok
}

func stringValue(value any) string {
	typed, _ := value.(string)
	return typed
}

func boolValue(value any) bool {
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return typed == "true"
	default:
		return false
	}
}

func intValue(value any) int {
	switch typed := value.(type) {
	case float64:
		return int(typed)
	case int:
		return typed
	case string:
		number, _ := strconv.Atoi(typed)
		return number
	default:
		return 0
	}
}

func intSlice(value any) []int {
	items := asAnySlice(value)
	out := make([]int, 0, len(items))
	for _, item := range items {
		out = append(out, intValue(item))
	}
	return out
}

func numberStrings(value any) []string {
	items := asAnySlice(value)
	out := make([]string, 0, len(items))
	for _, item := range items {
		switch typed := item.(type) {
		case float64:
			out = append(out, strconv.Itoa(int(typed)))
		case int:
			out = append(out, strconv.Itoa(typed))
		case string:
			out = append(out, typed)
		}
	}
	return out
}

func stringSlice(value any) []string {
	switch typed := value.(type) {
	case []string:
		return append([]string{}, typed...)
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	default:
		return []string{}
	}
}

func valueStrings(value any) []string {
	return stringSlice(value)
}

func sliceToSet(values []string) map[string]struct{} {
	out := make(map[string]struct{}, len(values))
	for _, value := range values {
		out[value] = struct{}{}
	}
	return out
}

func asAnySlice(value any) []any {
	typed, _ := value.([]any)
	return typed
}

func asMapSlice(value any) []map[string]any {
	items, _ := value.([]any)
	out := make([]map[string]any, 0, len(items))
	for _, item := range items {
		if typed, ok := item.(map[string]any); ok {
			out = append(out, typed)
		}
	}
	return out
}

func cloneMap(value map[string]any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(encoded, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func ensureMap(parent map[string]any, key string) map[string]any {
	if current, ok := parent[key].(map[string]any); ok {
		return current
	}
	next := map[string]any{}
	parent[key] = next
	return next
}

func ensureConfigMap(value any) map[string]any {
	current, _ := value.(map[string]any)
	return current
}

func ensureSliceMap(parent map[string]any, key string) []map[string]any {
	if current := asMapSlice(parent[key]); current != nil {
		return current
	}
	parent[key] = []any{}
	return []map[string]any{}
}

func toAnySlice(values []map[string]any) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func toAnyStringSlice(values []string) []any {
	out := make([]any, 0, len(values))
	for _, value := range values {
		out = append(out, value)
	}
	return out
}

func appendUniqueString(values []string, target string) []string {
	for _, value := range values {
		if value == target {
			return values
		}
	}
	return append(values, target)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func cipherName(cipherType int) string {
	switch cipherType {
	case 5:
		return "aes-128-gcm"
	case 6:
		return "aes-256-gcm"
	case 7:
		return "chacha20-poly1305"
	case 8:
		return "xchacha20-poly1305"
	default:
		return "chacha20-ietf-poly1305"
	}
}
