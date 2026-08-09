package node

import (
	"context"
	"crypto/md5"
	"encoding/base64"
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
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/remnawave/remnawave-node-go/internal/config"
	"github.com/remnawave/remnawave-node-go/internal/coreapi"
	"github.com/remnawave/remnawave-node-go/internal/state"
	"github.com/remnawave/remnawave-node-go/internal/statname"
	"github.com/remnawave/remnawave-node-go/internal/supervisor"
	"github.com/remnawave/remnawave-node-go/internal/system"
	"google.golang.org/grpc/credentials/insecure"
)

const (
	xrayProcessName    = "xray"
	singBoxProcessName = "sing-box"
	nftTableName       = "remnanode"
	xrayAPITag         = "REMNAWAVE_API"
	xrayAPIInboundTag  = "REMNAWAVE_API_INBOUND"
	torrentOutboundTag = "RW_TB_OUTBOUND_BLOCK"
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
		"autoDetectInterface": "auto_detect_interface",
		"certificatePath":     "certificate_path",
		"congestionControl":   "congestion_control",
		"domainSuffix":        "domain_suffix",
		"downloadDetour":      "download_detour",
		"cacheFile":           "cache_file",
		"ipIsPrivate":         "ip_is_private",
		"keyPath":             "key_path",
		"listenPort":          "listen_port",
		"ruleSet":             "rule_set",
		"serverPort":          "server_port",
	}
)

type Manager struct {
	cfg        config.Config
	state      *state.Runtime
	logger     *slog.Logger
	supervisor *supervisor.Client
	network    *system.NetworkMonitor
	nftReady   bool
	startedAt  time.Time
	coreMu     sync.Mutex
	apiTLS     *coreapi.MTLSBundle
	xrayStats  coreapi.StatsClient
	singStats  coreapi.StatsClient
	xrayHandle coreapi.HandlerClient
	xrayRoute  coreapi.RoutingClient
}

type StartRequest struct {
	CoreType      string         `json:"coreType"`
	Internals     startInternals `json:"internals"`
	XrayConfig    map[string]any `json:"xrayConfig"`
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
	Plugin *struct {
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
	bundle, err := coreapi.GenerateMTLSBundle()
	if err != nil {
		return nil, fmt.Errorf("generate internal API certificates: %w", err)
	}
	credentials, err := bundle.ClientCredentials()
	if err != nil {
		return nil, err
	}
	xrayStats, err := coreapi.NewXrayStatsClient(fmt.Sprintf("127.0.0.1:%d", cfg.XtlsAPIPort), credentials)
	if err != nil {
		return nil, err
	}
	singStats, err := coreapi.NewSingBoxStatsClient(fmt.Sprintf("127.0.0.1:%d", singBoxV2RayAPIPort(cfg)), insecure.NewCredentials())
	if err != nil {
		_ = xrayStats.Close()
		return nil, err
	}
	xrayHandler, err := coreapi.NewXrayHandlerClient(fmt.Sprintf("127.0.0.1:%d", cfg.XtlsAPIPort), credentials)
	if err != nil {
		_ = xrayStats.Close()
		_ = singStats.Close()
		return nil, err
	}
	xrayRouting, err := coreapi.NewXrayRoutingClient(fmt.Sprintf("127.0.0.1:%d", cfg.XtlsAPIPort), credentials)
	if err != nil {
		_ = xrayStats.Close()
		_ = singStats.Close()
		_ = xrayHandler.Close()
		return nil, err
	}
	return &Manager{
		cfg:        cfg,
		state:      runtimeState,
		logger:     logger,
		supervisor: client,
		network:    network,
		nftReady:   commandExists("nft") && hasNetAdmin(),
		startedAt:  time.Now(),
		apiTLS:     bundle,
		xrayStats:  xrayStats,
		singStats:  singStats,
		xrayHandle: xrayHandler,
		xrayRoute:  xrayRouting,
	}, nil
}

func (m *Manager) Close() error {
	var first error
	if m.xrayStats != nil {
		first = m.xrayStats.Close()
	}
	if m.singStats != nil {
		if err := m.singStats.Close(); first == nil {
			first = err
		}
	}
	if m.xrayHandle != nil {
		if err := m.xrayHandle.Close(); first == nil {
			first = err
		}
	}
	if m.xrayRoute != nil {
		if err := m.xrayRoute.Close(); first == nil {
			first = err
		}
	}
	return first
}

func (m *Manager) SyncEnvironment(ctx context.Context) {
	xrayVersion := m.readVersion(ctx, "/usr/local/bin/xray", "-version")
	singBoxVersion := m.readVersion(ctx, "/usr/local/bin/sing-box", "version")
	m.state.SetCoreVersions(xrayVersion, singBoxVersion)
	m.refreshOnlineStatus(ctx)
}

// SyncProcessStatus refreshes the inexpensive process state without spawning
// the core binaries to rediscover versions. Versions are stable for the life
// of a container and are loaded by SyncEnvironment at startup/start time.
func (m *Manager) SyncProcessStatus(ctx context.Context) {
	m.refreshOnlineStatus(ctx)
}

func (m *Manager) InternalConfig() map[string]any {
	return m.state.XrayConfig()
}

func (m *Manager) Start(ctx context.Context, request StartRequest, remoteIP string) map[string]any {
	m.coreMu.Lock()
	defer m.coreMu.Unlock()

	m.SyncEnvironment(ctx)

	coreType := state.CoreTypeXRAY
	if strings.EqualFold(request.CoreType, string(state.CoreTypeSingBox)) || strings.EqualFold(request.CoreType, "SING_BOX") {
		coreType = state.CoreTypeSingBox
	}

	snapshot := system.SystemSnapshot(m.network)
	shouldRestart := m.shouldRestartCore(coreType, request.Internals.ForceRestart, request.Internals.Hashes)

	switch coreType {
	case state.CoreTypeSingBox:
		config := applySingBoxAPIConfig(normalizeSingBoxKeys(cloneMap(request.SingBoxConfig)), m.cfg)
		if len(config) == 0 {
			return wrapStartResponse(false, nil, ptrString("singBoxConfig is required for SING_BOX core"), m.state.NodeVersion(), snapshot, string(coreType), m.coreVersions())
		}
		shouldRestart = shouldRestart || !reflect.DeepEqual(m.state.SingBoxConfig(), config)
		m.state.SetSingBoxConfig(config)
		if shouldRestart {
			if err := m.restartSingBox(ctx, config); err != nil {
				return wrapStartResponse(false, nil, ptrString(err.Error()), m.state.NodeVersion(), snapshot, string(coreType), m.coreVersions())
			}
		}
	case state.CoreTypeXRAY:
		config := applyXrayAPIConfig(cloneMap(request.XrayConfig), m.cfg, m.state.PluginState(), m.apiTLS)
		if len(config) == 0 {
			return wrapStartResponse(false, nil, ptrString("xrayConfig is required for XRAY core"), m.state.NodeVersion(), snapshot, string(coreType), m.coreVersions())
		}
		shouldRestart = shouldRestart || !reflect.DeepEqual(m.state.XrayConfig(), config)
		m.state.SetXrayConfig(config)
		if shouldRestart {
			if err := m.restartXray(ctx); err != nil {
				return wrapStartResponse(false, nil, ptrString(err.Error()), m.state.NodeVersion(), snapshot, string(coreType), m.coreVersions())
			}
		}
	}

	m.state.SetLastHashes(request.Internals.Hashes)
	m.refreshOnlineStatus(ctx)
	xrayOnline, singBoxOnline := m.state.OnlineStatus()
	started := xrayOnline
	if coreType == state.CoreTypeSingBox {
		started = singBoxOnline
	}
	m.logger.Info("node start request handled", "core", coreType, "remote_ip", remoteIP, "restarted", shouldRestart)
	return wrapStartResponse(started, m.activeVersion(coreType), nil, m.state.NodeVersion(), snapshot, string(coreType), m.coreVersions())
}

func (m *Manager) shouldRestartCore(coreType state.CoreType, force bool, hashes state.StartHashes) bool {
	xrayOnline, singBoxOnline := m.state.OnlineStatus()
	targetOnline := xrayOnline
	if coreType == state.CoreTypeSingBox {
		targetOnline = singBoxOnline
	}
	return force ||
		m.cfg.DisableHashCheck ||
		m.state.RunningCoreType() != coreType ||
		!targetOnline ||
		m.state.ShouldRestart(hashes)
}

func (m *Manager) Stop(ctx context.Context) map[string]any {
	m.coreMu.Lock()
	defer m.coreMu.Unlock()

	_ = m.supervisor.StopProcess(ctx, xrayProcessName)
	_ = m.supervisor.StopProcess(ctx, singBoxProcessName)
	m.state.SetRunningCore("")
	m.state.SetOnlineStatus(false, false)
	m.state.Reset()
	return map[string]any{"response": map[string]any{"isStopped": true}}
}

func (m *Manager) Healthcheck(ctx context.Context) map[string]any {
	m.refreshOnlineStatus(ctx)
	xrayOnline, singBoxOnline := m.state.OnlineStatus()
	runningCore := m.state.RunningCore()
	coreOnline := xrayOnline
	if runningCore == string(state.CoreTypeSingBox) {
		coreOnline = singBoxOnline
	}
	var runningValue any
	if runningCore != "" {
		runningValue = runningCore
	}
	return map[string]any{
		"response": map[string]any{
			"isAlive":                  true,
			"xrayInternalStatusCached": coreOnline,
			"xrayVersion":              derefString(m.activeVersion(state.CoreTypeXRAY)),
			"runningCore":              runningValue,
			"supportedCores":           []string{string(state.CoreTypeXRAY), string(state.CoreTypeSingBox)},
			"coreVersions":             m.coreVersions(),
			"nodeVersion":              m.state.NodeVersion(),
		},
	}
}

func (m *Manager) GetSystemStats(ctx context.Context) (map[string]any, error) {
	runningCore := m.state.RunningCoreType()
	xrayOnline, singBoxOnline := m.state.OnlineStatus()
	if runningCore == "" ||
		(runningCore == state.CoreTypeXRAY && !xrayOnline) ||
		(runningCore == state.CoreTypeSingBox && !singBoxOnline) {
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
			"xrayInfo": coreStats,
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
	if m.state.RunningCoreType() != state.CoreTypeSingBox && m.xrayStats != nil {
		for _, username := range m.statUsernamesForUser(request.Username) {
			online, err := m.xrayStats.Online(ctx, username)
			if err == nil && online {
				return map[string]any{"response": map[string]any{"isOnline": true}}
			}
		}
		return map[string]any{"response": map[string]any{"isOnline": false}}
	}
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
	return m.xrayStats
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
	if m.state.RunningCoreType() != state.CoreTypeSingBox && m.xrayStats != nil {
		items := m.xrayUserIPs(ctx, request.UserID)
		sort.Slice(items, func(i, j int) bool { return items[i].LastSeen.After(items[j].LastSeen) })
		return map[string]any{"response": map[string]any{"ips": formatSeenIPs(items)}}
	}
	items, err := m.userConnectionProvider().UserIPList(ctx, request.UserID)
	if err != nil {
		return map[string]any{"response": map[string]any{"ips": []map[string]any{}}}
	}
	return map[string]any{"response": map[string]any{"ips": formatSeenIPs(items)}}
}

func (m *Manager) GetUsersIPList(ctx context.Context) map[string]any {
	if m.state.RunningCoreType() != state.CoreTypeSingBox && m.xrayStats != nil {
		users, err := m.xrayStats.OnlineUsers(ctx)
		if err != nil {
			return map[string]any{"response": map[string]any{"users": []map[string]any{}}}
		}
		all := make(map[string][]state.SeenIP, len(users))
		for _, userID := range users {
			ips, err := m.xrayStats.UserIPs(ctx, userID)
			realUserID := statname.UserID(userID)
			if err != nil {
				if _, ok := all[realUserID]; !ok {
					all[realUserID] = []state.SeenIP{}
				}
				continue
			}
			for ip, seen := range ips {
				all[realUserID] = append(all[realUserID], state.SeenIP{IP: ip, LastSeen: time.Unix(seen, 0)})
			}
		}
		return map[string]any{"response": map[string]any{"users": formatUserIPLists(all)}}
	}
	items, err := m.userConnectionProvider().UsersIPList(ctx)
	if err != nil {
		return map[string]any{"response": map[string]any{"users": []map[string]any{}}}
	}
	return map[string]any{"response": map[string]any{"users": formatUserIPLists(items)}}
}

func (m *Manager) GetInboundUsers(ctx context.Context, request GetInboundUsersRequest) map[string]any {
	if m.state.RunningCoreType() == state.CoreTypeXRAY && m.xrayHandle != nil {
		users, err := m.xrayHandle.InboundUsers(ctx, request.Tag)
		if err == nil {
			items := make([]map[string]any, 0, len(users))
			for _, user := range users {
				items = append(items, map[string]any{"username": statname.UserID(user.Username), "level": user.Level, "protocol": user.Protocol})
			}
			return map[string]any{"response": map[string]any{"users": items}}
		}
	}
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
	if m.state.RunningCoreType() == state.CoreTypeXRAY && m.xrayHandle != nil {
		if count, err := m.xrayHandle.InboundUsersCount(ctx, request.Tag); err == nil {
			return map[string]any{"response": map[string]any{"count": count}}
		}
	}
	return map[string]any{"response": map[string]any{"count": len(m.state.InboundUsers(request.Tag))}}
}

func (m *Manager) AddUser(ctx context.Context, request AddUserRequest) map[string]any {
	m.coreMu.Lock()
	defer m.coreMu.Unlock()

	if m.state.RunningCoreType() == state.CoreTypeXRAY && m.xrayHandle != nil {
		if err := m.addXrayUsersLive(ctx, request.Data); err != nil {
			return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
		}
		if err := m.applyAddUserRequest(request); err != nil {
			return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
		}
		return map[string]any{"response": map[string]any{"success": true, "error": nil}}
	}
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

	if m.state.RunningCoreType() == state.CoreTypeXRAY && m.xrayHandle != nil {
		if err := m.addBulkXrayUsersLive(ctx, request); err != nil {
			return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
		}
		if err := m.applyAddUsersRequest(request); err != nil {
			return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
		}
		return map[string]any{"response": map[string]any{"success": true, "error": nil}}
	}
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

	if m.state.RunningCoreType() == state.CoreTypeXRAY && m.xrayHandle != nil {
		ips := m.xrayUserIPs(ctx, request.Username)
		if err := m.removeXrayUserLive(ctx, request.Username); err != nil {
			return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
		}
		_ = m.removeUserEverywhere(request.Username)
		for _, item := range ips {
			m.dropConnections(item.IP)
		}
		return map[string]any{"response": map[string]any{"success": true, "error": nil}}
	}
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

	if m.state.RunningCoreType() == state.CoreTypeXRAY && m.xrayHandle != nil {
		for _, user := range request.Users {
			ips := m.xrayUserIPs(ctx, user.UserID)
			if err := m.removeXrayUserLive(ctx, user.UserID); err != nil {
				return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
			}
			_ = m.removeUserEverywhere(user.UserID)
			for _, item := range ips {
				m.dropConnections(item.IP)
			}
		}
		return map[string]any{"response": map[string]any{"success": true, "error": nil}}
	}
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
	return newUserConnectionProvider(m.cfg.XtlsAPIPort, m.cfg.SingBoxAPIPort, m.cfg.InternalRESTToken, m.state)
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
	if m.state.RunningCoreType() != state.CoreTypeXRAY || m.xrayRoute == nil {
		return map[string]any{"response": map[string]any{"success": false, "error": "Vision routing is only available for XRAY"}}
	}
	if err := m.xrayRoute.AddSourceIPRule(ctx, visionRuleTag(request.IP), "BLOCK", request.IP, true); err != nil {
		return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
	}
	return map[string]any{"response": map[string]any{"success": true, "error": nil}}
}

func (m *Manager) UnblockIP(ctx context.Context, request VisionIPRequest) map[string]any {
	if m.state.RunningCoreType() != state.CoreTypeXRAY || m.xrayRoute == nil {
		return map[string]any{"response": map[string]any{"success": false, "error": "Vision routing is only available for XRAY"}}
	}
	if err := m.xrayRoute.RemoveRule(ctx, visionRuleTag(request.IP)); err != nil {
		return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
	}
	return map[string]any{"response": map[string]any{"success": true, "error": nil}}
}

func visionRuleTag(ip string) string {
	value := fmt.Sprintf("string:%d:%s", len(ip), ip)
	digest := md5.Sum([]byte(value))
	return hex.EncodeToString(digest[:])
}

func (m *Manager) SyncPlugin(ctx context.Context, request PluginSyncRequest) map[string]any {
	m.coreMu.Lock()
	defer m.coreMu.Unlock()

	current := m.state.PluginState()
	if request.Plugin == nil {
		current = emptyPluginState()
		if m.nftReady {
			if err := m.recreateNFTables(ctx); err != nil {
				return map[string]any{"response": map[string]any{"accepted": false}}
			}
		}
		m.state.SetPluginState(current)
		return map[string]any{"response": map[string]any{"accepted": true}}
	}

	next := emptyPluginState()
	next.ConfigHash = state.ConfigHash(request.Plugin.Config)
	next.ActivePlugin = &state.PluginMeta{UUID: request.Plugin.UUID, Name: request.Plugin.Name}
	sharedLists := readSharedLists(request.Plugin.Config)
	configureConnectionDrop(&next, request.Plugin.Config, sharedLists)
	configureTorrentBlocker(&next, request.Plugin.Config, sharedLists)
	configureIngressFilter(&next, request.Plugin.Config, sharedLists)
	configureEgressFilter(&next, request.Plugin.Config, sharedLists)

	changedTorrent := current.TorrentEnabled != next.TorrentEnabled || current.TorrentDuration != next.TorrentDuration || !sameStringSet(current.TorrentIncludeRuleTags, next.TorrentIncludeRuleTags)
	if m.nftReady {
		if err := m.recreateNFTables(ctx); err != nil {
			return map[string]any{"response": map[string]any{"accepted": false}}
		}
		if err := m.syncNFTState(ctx, next); err != nil {
			return map[string]any{"response": map[string]any{"accepted": false}}
		}
	}
	m.state.SetPluginState(next)
	if changedTorrent {
		if err := m.restartCurrentCore(ctx); err != nil {
			return map[string]any{"response": map[string]any{"accepted": false}}
		}
	}
	return map[string]any{"response": map[string]any{"accepted": true}}
}

func (m *Manager) CollectReports() map[string]any {
	reports := m.state.FlushTorrentReports()
	items := make([]map[string]any, 0, len(reports))
	for _, report := range reports {
		items = append(items, map[string]any{
			"actionReport": report.ActionReport,
			"xrayReport":   report.XrayReport,
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
		XrayReport: payload,
	}
	m.state.AddTorrentReport(report)
}

func (m *Manager) restartCurrentCore(ctx context.Context) error {
	m.state.MarkHashesDirty()
	switch m.state.RunningCoreType() {
	case state.CoreTypeSingBox:
		return m.restartSingBox(ctx, m.state.SingBoxConfig())
	case state.CoreTypeXRAY:
		return m.restartXray(ctx)
	default:
		return nil
	}
}

func (m *Manager) restartXray(ctx context.Context) error {
	if err := os.MkdirAll(filepath.Dir(m.cfg.XrayConfigPath), 0o755); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(m.state.XrayConfig(), "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(m.cfg.XrayConfigPath, encoded, 0o644); err != nil {
		return err
	}
	_ = m.supervisor.StopProcess(ctx, singBoxProcessName)
	_ = m.supervisor.StopProcess(ctx, xrayProcessName)
	if err := m.supervisor.StartProcess(ctx, xrayProcessName); err != nil {
		return err
	}
	m.state.SetRunningCore(state.CoreTypeXRAY)
	m.refreshOnlineStatus(ctx)
	return nil
}

func (m *Manager) restartSingBox(ctx context.Context, config map[string]any) error {
	config = applySingBoxAPIConfig(cloneMap(config), m.cfg)
	m.state.SetSingBoxConfig(config)
	if err := os.MkdirAll(filepath.Dir(m.cfg.SingBoxConfigPath), 0o755); err != nil {
		return err
	}
	encoded, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(m.cfg.SingBoxConfigPath, encoded, 0o644); err != nil {
		return err
	}
	_ = m.supervisor.StopProcess(ctx, xrayProcessName)
	_ = m.supervisor.StopProcess(ctx, singBoxProcessName)
	if err := m.supervisor.StartProcess(ctx, singBoxProcessName); err != nil {
		return err
	}
	m.state.SetRunningCore(state.CoreTypeSingBox)
	m.refreshOnlineStatus(ctx)
	return nil
}

func (m *Manager) refreshOnlineStatus(ctx context.Context) {
	xrayInfo, _ := m.supervisor.GetProcessInfo(ctx, xrayProcessName)
	singBoxInfo, _ := m.supervisor.GetProcessInfo(ctx, singBoxProcessName)
	m.state.SetOnlineStatus(xrayInfo.State == supervisor.StateRunning, singBoxInfo.State == supervisor.StateRunning)
}

func (m *Manager) activeVersion(coreType state.CoreType) *string {
	xrayVersion, singBoxVersion := m.state.CoreVersions()
	if coreType == state.CoreTypeSingBox {
		return singBoxVersion
	}
	return xrayVersion
}

func (m *Manager) coreVersions() map[string]any {
	xrayVersion, singBoxVersion := m.state.CoreVersions()
	return map[string]any{
		"xray":    derefString(xrayVersion),
		"singBox": derefString(singBoxVersion),
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
	case "xray", "rw-core":
		if len(fields) >= 2 && strings.EqualFold(fields[0], "xray") {
			return trimVersionPrefix(fields[1])
		}
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

func (m *Manager) addXrayUsersLive(ctx context.Context, users []AddUserItem) error {
	seen := map[string]struct{}{}
	for _, user := range users {
		if _, ok := seen[user.Username]; !ok {
			_ = m.removeXrayUserLive(ctx, user.Username)
			seen[user.Username] = struct{}{}
		}
		statsUsername := statname.UserInbound(user.Username, user.Tag)
		if err := m.xrayHandle.AddUser(ctx, user.Tag, coreapi.User{
			Type: user.Type, Username: statsUsername, Password: user.Password, UUID: user.UUID,
			Flow: user.Flow, CipherType: user.CipherType, IVCheck: user.IVCheck,
		}); err != nil {
			return fmt.Errorf("add Xray user %s to %s: %w", user.Username, user.Tag, err)
		}
	}
	return nil
}

func (m *Manager) addBulkXrayUsersLive(ctx context.Context, request AddUsersRequest) error {
	for _, user := range request.Users {
		_ = m.removeXrayUserLive(ctx, user.UserData.UserID)
		for _, inbound := range user.InboundData {
			password := user.UserData.TrojanPassword
			if inbound.Type == "shadowsocks" || inbound.Type == "shadowsocks22" {
				password = user.UserData.SSPassword
			}
			if inbound.Type == "shadowsocks22" {
				password = base64.StdEncoding.EncodeToString([]byte(password))
			}
			if inbound.Type == "hysteria" {
				password = user.UserData.VLESSUUID
			}
			statsUsername := statname.UserInbound(user.UserData.UserID, inbound.Tag)
			if err := m.xrayHandle.AddUser(ctx, inbound.Tag, coreapi.User{
				Type: inbound.Type, Username: statsUsername, Password: password,
				UUID: user.UserData.VLESSUUID, Flow: inbound.Flow,
			}); err != nil {
				return fmt.Errorf("add Xray user %s to %s: %w", user.UserData.UserID, inbound.Tag, err)
			}
		}
	}
	return nil
}

func (m *Manager) removeXrayUserLive(ctx context.Context, username string) error {
	tags := xrayInboundTags(m.state.XrayConfig())
	var lastErr error
	succeeded := 0
	for _, tag := range tags {
		for _, statsUsername := range []string{username, statname.UserInbound(username, tag)} {
			if err := m.xrayHandle.RemoveUser(ctx, tag, statsUsername); err != nil {
				lastErr = err
			} else {
				succeeded++
			}
		}
	}
	if len(tags) > 0 && succeeded == 0 {
		return fmt.Errorf("remove Xray user %s: %w", username, lastErr)
	}
	return nil
}

func (m *Manager) xrayUserIPs(ctx context.Context, username string) []state.SeenIP {
	if m.xrayStats == nil {
		return nil
	}
	seenByIP := map[string]time.Time{}
	for _, statsUsername := range m.statUsernamesForUser(username) {
		values, err := m.xrayStats.UserIPs(ctx, statsUsername)
		if err != nil {
			continue
		}
		for ip, seen := range values {
			lastSeen := time.Unix(seen, 0)
			if previous, ok := seenByIP[ip]; !ok || lastSeen.After(previous) {
				seenByIP[ip] = lastSeen
			}
		}
	}
	items := make([]state.SeenIP, 0, len(seenByIP))
	for ip, seen := range seenByIP {
		items = append(items, state.SeenIP{IP: ip, LastSeen: seen})
	}
	return items
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

func xrayInboundTags(config map[string]any) []string {
	tags := []string{}
	for _, inbound := range asMapSlice(config["inbounds"]) {
		tag := stringValue(inbound["tag"])
		if tag != "" && tag != xrayAPIInboundTag {
			tags = append(tags, tag)
		}
	}
	return tags
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
	case state.CoreTypeXRAY, "":
		config := m.state.XrayConfig()
		if err := addXrayUser(config, item); err != nil {
			return err
		}
		m.state.SetXrayConfig(config)
	}
	return nil
}

func (m *Manager) removeUserEverywhere(username string) error {
	switch m.state.RunningCoreType() {
	case state.CoreTypeSingBox:
		config := m.state.SingBoxConfig()
		removeSingBoxUser(config, username)
		m.state.SetSingBoxConfig(config)
	case state.CoreTypeXRAY, "":
		config := m.state.XrayConfig()
		removeXrayUser(config, username)
		m.state.SetXrayConfig(config)
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
		{"add", "set", "inet", nftTableName, "ingress-filter-ip", "{", "type", "ipv4_addr;", "}"},
		{"add", "set", "inet", nftTableName, "ingress-filter-ip6", "{", "type", "ipv6_addr;", "}"},
		{"add", "set", "inet", nftTableName, "egress-filter-ip", "{", "type", "ipv4_addr;", "}"},
		{"add", "set", "inet", nftTableName, "egress-filter-ip6", "{", "type", "ipv6_addr;", "}"},
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
		parsed := net.ParseIP(item)
		if parsed == nil || (parsed.To4() == nil) != ipv6 {
			continue
		}
		filtered = append(filtered, item)
	}
	if len(filtered) == 0 {
		return nil
	}
	args := []string{"add", "element", "inet", nftTableName, setName, "{", strings.Join(filtered, ", "), "}"}
	return m.runNft(ctx, args...)
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

func applyXrayAPIConfig(config map[string]any, cfg config.Config, pluginState state.PluginState, bundle *coreapi.MTLSBundle) map[string]any {
	if len(config) == 0 {
		return config
	}
	encodeXrayConfigUsers(config)
	apiTag := ensureXrayStatsConfig(config, cfg.XtlsAPIPort, bundle)
	routing := ensureMap(config, "routing")
	rules := ensureSliceMap(routing, "rules")
	if !hasXrayAPIRoute(rules, apiTag) {
		rules = append([]map[string]any{{
			"type":        "field",
			"inboundTag":  []any{xrayAPIInboundTag},
			"outboundTag": apiTag,
		}}, rules...)
	}
	if pluginState.TorrentEnabled {
		webhookURL := fmt.Sprintf("/%s:/internal/webhook?token=%s", cfg.InternalSocketPath, cfg.InternalRESTToken)
		rule := map[string]any{
			"protocol":    []any{"bittorrent"},
			"outboundTag": torrentOutboundTag,
			"webhook": map[string]any{
				"url":           webhookURL,
				"deduplication": 5,
			},
		}
		rules = append([]map[string]any{rule}, rules...)
		for _, existing := range rules {
			if _, ok := pluginState.TorrentIncludeRuleTags[stringValue(existing["ruleTag"])]; ok {
				existing["webhook"] = map[string]any{"url": webhookURL, "deduplication": 5}
			}
		}
		outbounds := ensureSliceMap(config, "outbounds")
		found := false
		for _, outbound := range outbounds {
			if stringValue(outbound["tag"]) == torrentOutboundTag {
				found = true
				break
			}
		}
		if !found {
			outbounds = append(outbounds, map[string]any{"tag": torrentOutboundTag, "protocol": "blackhole"})
			config["outbounds"] = toAnySlice(outbounds)
		}
	}
	routing["rules"] = toAnySlice(rules)
	config["routing"] = routing
	return config
}

func ensureXrayStatsConfig(config map[string]any, apiPort int, bundle *coreapi.MTLSBundle) string {
	if config["stats"] == nil {
		config["stats"] = map[string]any{}
	}

	api := ensureMap(config, "api")
	apiTag := firstNonEmpty(stringValue(api["tag"]), xrayAPITag)
	api["tag"] = apiTag
	delete(api, "listen")
	services := valueStrings(api["services"])
	for _, service := range []string{"HandlerService", "StatsService", "RoutingService"} {
		services = appendUniqueString(services, service)
	}
	api["services"] = toAnyStringSlice(services)
	config["api"] = api

	policy := ensureMap(config, "policy")
	levels := ensureMap(policy, "levels")
	level0 := ensureMap(levels, "0")
	level0["statsUserUplink"] = true
	level0["statsUserDownlink"] = true
	level0["statsUserOnline"] = true

	system := ensureMap(policy, "system")
	system["statsInboundUplink"] = true
	system["statsInboundDownlink"] = true
	system["statsOutboundUplink"] = true
	system["statsOutboundDownlink"] = true
	policy["levels"] = levels
	policy["system"] = system
	config["policy"] = policy

	if apiPort <= 0 {
		return apiTag
	}

	inbounds := ensureSliceMap(config, "inbounds")
	apiInbound := map[string]any{
		"tag":      xrayAPIInboundTag,
		"listen":   "127.0.0.1",
		"port":     apiPort,
		"protocol": "dokodemo-door",
		"settings": map[string]any{
			"address": "127.0.0.1",
		},
	}
	if bundle != nil {
		apiInbound["streamSettings"] = map[string]any{
			"security": "tls",
			"tlsSettings": map[string]any{
				"alpn":              []any{"h2"},
				"serverName":        coreapi.InternalServerName,
				"disableSystemRoot": true,
				"rejectUnknownSni":  true,
				"certificates": []any{
					map[string]any{"certificate": pemLines(bundle.ServerCertPEM), "key": pemLines(bundle.ServerKeyPEM)},
					map[string]any{"usage": "verify", "certificate": pemLines(bundle.CACertPEM)},
				},
			},
		}
	}
	replaced := false
	for idx, inbound := range inbounds {
		if stringValue(inbound["tag"]) != xrayAPIInboundTag && stringValue(inbound["tag"]) != apiTag {
			continue
		}
		inbounds[idx] = apiInbound
		replaced = true
		break
	}
	if !replaced {
		inbounds = append(inbounds, apiInbound)
	}
	config["inbounds"] = toAnySlice(inbounds)

	return apiTag
}

func pemLines(value string) []any {
	lines := strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n")
	out := make([]any, 0, len(lines))
	for _, line := range lines {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func hasXrayAPIRoute(rules []map[string]any, apiTag string) bool {
	for _, rule := range rules {
		if stringValue(rule["outboundTag"]) != apiTag {
			continue
		}
		for _, inboundTag := range valueStrings(rule["inboundTag"]) {
			if inboundTag == xrayAPIInboundTag {
				return true
			}
		}
	}
	return false
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

func encodeXrayConfigUsers(config map[string]any) {
	for _, inbound := range asMapSlice(config["inbounds"]) {
		tag := stringValue(inbound["tag"])
		if tag == "" || tag == xrayAPIInboundTag {
			continue
		}
		settings := ensureMap(inbound, "settings")
		clients := asMapSlice(settings["clients"])
		for _, client := range clients {
			userID := statname.UserID(firstNonEmpty(stringValue(client["email"]), stringValue(client["name"])))
			if userID == "" {
				continue
			}
			client["email"] = statname.UserInbound(userID, tag)
		}
		settings["clients"] = toAnySlice(clients)
		inbound["settings"] = settings
	}
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

func addXrayUser(config map[string]any, item AddUserItem) error {
	for _, inbound := range asMapSlice(config["inbounds"]) {
		if stringValue(inbound["tag"]) != item.Tag {
			continue
		}
		settings := ensureMap(inbound, "settings")
		clients := ensureSliceMap(settings, "clients")
		client := map[string]any{"email": statname.UserInbound(item.Username, item.Tag)}
		switch stringValue(inbound["protocol"]) {
		case "trojan":
			client["password"] = item.Password
			client["id"] = item.UUID
		case "vless":
			client["id"] = item.UUID
			client["flow"] = item.Flow
		case "hysteria":
			client["id"] = item.Password
			client["auth"] = item.Password
		case "shadowsocks":
			client["password"] = item.Password
			client["id"] = item.UUID
			client["method"] = cipherName(item.CipherType)
		default:
			return fmt.Errorf("protocol %s is not supported", stringValue(inbound["protocol"]))
		}
		clients = append(clients, client)
		settings["clients"] = toAnySlice(clients)
		inbound["settings"] = settings
		return nil
	}
	return fmt.Errorf("inbound %s not found", item.Tag)
}

func removeXrayUser(config map[string]any, username string) {
	for _, inbound := range asMapSlice(config["inbounds"]) {
		settings := ensureMap(inbound, "settings")
		clients := asMapSlice(settings["clients"])
		filtered := make([]map[string]any, 0, len(clients))
		for _, client := range clients {
			if statname.UserID(firstNonEmpty(stringValue(client["email"]), stringValue(client["name"]))) == username {
				continue
			}
			filtered = append(filtered, client)
		}
		settings["clients"] = toAnySlice(filtered)
		inbound["settings"] = settings
	}
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

func readSharedLists(config map[string]any) map[string][]string {
	out := map[string][]string{}
	for _, list := range asMapSlice(config["sharedLists"]) {
		name := stringValue(list["name"])
		if name == "" {
			continue
		}
		items := make([]string, 0)
		for _, item := range asAnySlice(list["items"]) {
			if value, ok := item.(string); ok {
				items = append(items, value)
			}
		}
		out[name] = items
	}
	return out
}

func configureConnectionDrop(target *state.PluginState, config map[string]any, shared map[string][]string) {
	plugin := ensureConfigMap(config["connectionDrop"])
	if !boolValue(plugin["enabled"]) {
		return
	}
	target.ConnectionDropWhitelist = sliceToSet(resolveIPList(stringSlice(plugin["whitelistIps"]), shared))
}

func configureTorrentBlocker(target *state.PluginState, config map[string]any, shared map[string][]string) {
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

func configureIngressFilter(target *state.PluginState, config map[string]any, shared map[string][]string) {
	plugin := ensureConfigMap(config["ingressFilter"])
	if !boolValue(plugin["enabled"]) {
		return
	}
	target.IngressBlocked = resolveIPList(stringSlice(plugin["blockedIps"]), shared)
}

func configureEgressFilter(target *state.PluginState, config map[string]any, shared map[string][]string) {
	plugin := ensureConfigMap(config["egressFilter"])
	if !boolValue(plugin["enabled"]) {
		return
	}
	target.EgressBlockedIPs = resolveIPList(stringSlice(plugin["blockedIps"]), shared)
	target.EgressBlockedPorts = intSlice(plugin["blockedPorts"])
}

func emptyPluginState() state.PluginState {
	return state.PluginState{
		ConnectionDropWhitelist: map[string]struct{}{},
		TorrentIgnoredIPs:       map[string]struct{}{},
		TorrentIgnoredUsers:     map[string]struct{}{},
		TorrentIncludeRuleTags:  map[string]struct{}{},
	}
}

func resolveIPList(values []string, shared map[string][]string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if strings.HasPrefix(value, "ext:") {
			out = append(out, shared[value]...)
			continue
		}
		out = append(out, value)
	}
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

func wrapStartResponse(started bool, version *string, err *string, nodeVersion string, snapshot system.Snapshot, runningCore string, versions map[string]any) map[string]any {
	return map[string]any{
		"response": map[string]any{
			"isStarted":    started,
			"version":      derefString(version),
			"runningCore":  runningCore,
			"coreVersions": versions,
			"error":        derefString(err),
			"nodeInformation": map[string]any{
				"version": nodeVersion,
			},
			"system": snapshot,
		},
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
