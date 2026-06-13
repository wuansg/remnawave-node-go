package node

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/remnawave/remnawave-node-go/internal/config"
	"github.com/remnawave/remnawave-node-go/internal/state"
	"github.com/remnawave/remnawave-node-go/internal/supervisor"
	"github.com/remnawave/remnawave-node-go/internal/system"
)

const (
	xrayProcessName    = "xray"
	singBoxProcessName = "sing-box"
	nftTableName       = "remnanode"
)

var (
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
		"ipIsPrivate":         "ip_is_private",
		"keyPath":             "key_path",
		"listenPort":          "listen_port",
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

func NewManager(cfg config.Config, runtimeState *state.Runtime, logger *slog.Logger, client *supervisor.Client, network *system.NetworkMonitor) *Manager {
	return &Manager{
		cfg:        cfg,
		state:      runtimeState,
		logger:     logger,
		supervisor: client,
		network:    network,
		nftReady:   commandExists("nft"),
		startedAt:  time.Now(),
	}
}

func (m *Manager) SyncEnvironment(ctx context.Context) {
	xrayVersion := m.readVersion(ctx, "/usr/local/bin/xray", "-version")
	singBoxVersion := m.readVersion(ctx, "/usr/local/bin/sing-box", "version")
	m.state.SetCoreVersions(xrayVersion, singBoxVersion)
	m.refreshOnlineStatus(ctx)
}

func (m *Manager) InternalConfig() map[string]any {
	return m.state.XrayConfig()
}

func (m *Manager) Start(ctx context.Context, request StartRequest, remoteIP string) map[string]any {
	m.SyncEnvironment(ctx)

	coreType := state.CoreTypeXRAY
	if strings.EqualFold(request.CoreType, string(state.CoreTypeSingBox)) || strings.EqualFold(request.CoreType, "SING_BOX") {
		coreType = state.CoreTypeSingBox
	}

	snapshot := system.SystemSnapshot(m.network)
	shouldRestart := request.Internals.ForceRestart || m.state.ShouldRestart(request.Internals.Hashes)

	switch coreType {
	case state.CoreTypeSingBox:
		config := normalizeSingBoxKeys(cloneMap(request.SingBoxConfig))
		if len(config) == 0 {
			return wrapStartResponse(false, nil, ptrString("singBoxConfig is required for SING_BOX core"), m.state.NodeVersion(), snapshot, string(coreType), m.coreVersions())
		}
		m.state.SetSingBoxConfig(config)
		m.state.SetRunningCore(coreType)
		if shouldRestart {
			if err := m.restartSingBox(ctx, config); err != nil {
				return wrapStartResponse(false, nil, ptrString(err.Error()), m.state.NodeVersion(), snapshot, string(coreType), m.coreVersions())
			}
		}
	case state.CoreTypeXRAY:
		config := applyXrayAPIConfig(cloneMap(request.XrayConfig), m.cfg, m.state.PluginState())
		if len(config) == 0 {
			return wrapStartResponse(false, nil, ptrString("xrayConfig is required for XRAY core"), m.state.NodeVersion(), snapshot, string(coreType), m.coreVersions())
		}
		m.state.SetXrayConfig(config)
		m.state.SetRunningCore(coreType)
		if shouldRestart {
			if err := m.restartXray(ctx); err != nil {
				return wrapStartResponse(false, nil, ptrString(err.Error()), m.state.NodeVersion(), snapshot, string(coreType), m.coreVersions())
			}
		}
	}

	m.state.SetLastHashes(request.Internals.Hashes)
	m.refreshOnlineStatus(ctx)
	xrayOnline, singBoxOnline := m.state.OnlineStatus()
	started := xrayOnline || singBoxOnline
	m.logger.Info("node start request handled", "core", coreType, "remote_ip", remoteIP, "restarted", shouldRestart)
	return wrapStartResponse(started, m.activeVersion(coreType), nil, m.state.NodeVersion(), snapshot, string(coreType), m.coreVersions())
}

func (m *Manager) Stop(ctx context.Context) map[string]any {
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
	alive := xrayOnline || singBoxOnline
	var runningValue any
	if runningCore != "" {
		runningValue = runningCore
	}
	return map[string]any{
		"response": map[string]any{
			"isAlive":                  alive,
			"xrayInternalStatusCached": alive,
			"xrayVersion":              derefString(m.activeVersion(m.state.RunningCoreType())),
			"runningCore":              runningValue,
			"supportedCores":           []string{string(state.CoreTypeXRAY), string(state.CoreTypeSingBox)},
			"coreVersions":             m.coreVersions(),
			"nodeVersion":              m.state.NodeVersion(),
		},
	}
}

func (m *Manager) GetSystemStats() map[string]any {
	snapshot := system.SystemSnapshot(m.network)
	pluginState := m.state.PluginState()
	return map[string]any{
		"response": map[string]any{
			"xrayInfo": system.CurrentProcessStats(int64(time.Since(m.startedAt).Seconds())),
			"plugins": map[string]any{
				"torrentBlocker": map[string]any{
					"reportsCount": len(pluginState.TorrentReports),
				},
			},
			"system": map[string]any{
				"stats": snapshot.Stats,
			},
		},
	}
}

func (m *Manager) GetUserOnlineStatus(request GetUserOnlineStatusRequest) map[string]any {
	now := time.Now()
	online := false
	for _, item := range m.state.UserIPs(request.Username) {
		if now.Sub(item.LastSeen) <= 10*time.Minute {
			online = true
			break
		}
	}
	return map[string]any{"response": map[string]any{"isOnline": online}}
}

func (m *Manager) GetUsersStats() map[string]any {
	users := []map[string]any{}
	all := m.state.InboundUsersMap()
	seen := map[string]struct{}{}
	for _, inboundUsers := range all {
		for _, user := range inboundUsers {
			if _, ok := seen[user.UserID]; ok {
				continue
			}
			seen[user.UserID] = struct{}{}
			users = append(users, map[string]any{
				"username": user.UserID,
				"uplink":   0,
				"downlink": 0,
			})
		}
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i]["username"].(string) < users[j]["username"].(string)
	})
	return map[string]any{"response": map[string]any{"users": users}}
}

func (m *Manager) GetInboundStats(request GetTagStatsRequest) map[string]any {
	return map[string]any{"response": map[string]any{"inbound": request.Tag, "uplink": 0, "downlink": 0}}
}

func (m *Manager) GetOutboundStats(request GetTagStatsRequest) map[string]any {
	return map[string]any{"response": map[string]any{"outbound": request.Tag, "uplink": 0, "downlink": 0}}
}

func (m *Manager) GetAllInboundStats() map[string]any {
	items := []map[string]any{}
	for tag := range m.state.InboundUsersMap() {
		items = append(items, map[string]any{"inbound": tag, "uplink": 0, "downlink": 0})
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i]["inbound"].(string) < items[j]["inbound"].(string)
	})
	return map[string]any{"response": map[string]any{"inbounds": items}}
}

func (m *Manager) GetAllOutboundStats() map[string]any {
	return map[string]any{"response": map[string]any{"outbounds": []map[string]any{}}}
}

func (m *Manager) GetCombinedStats() map[string]any {
	inbounds := m.GetAllInboundStats()["response"].(map[string]any)["inbounds"]
	return map[string]any{"response": map[string]any{"inbounds": inbounds, "outbounds": []map[string]any{}}}
}

func (m *Manager) GetUserIPList(request GetUserIPListRequest) map[string]any {
	items := []map[string]any{}
	for _, ip := range m.state.UserIPs(request.UserID) {
		items = append(items, map[string]any{
			"ip":       ip.IP,
			"lastSeen": ip.LastSeen.Format(time.RFC3339),
		})
	}
	return map[string]any{"response": map[string]any{"ips": items}}
}

func (m *Manager) GetUsersIPList() map[string]any {
	users := []map[string]any{}
	for userID, items := range m.state.AllUserIPs() {
		ips := []map[string]any{}
		for _, ip := range items {
			ips = append(ips, map[string]any{
				"ip":       ip.IP,
				"lastSeen": ip.LastSeen.Format(time.RFC3339),
			})
		}
		users = append(users, map[string]any{
			"userId": userID,
			"ips":    ips,
		})
	}
	sort.Slice(users, func(i, j int) bool {
		return users[i]["userId"].(string) < users[j]["userId"].(string)
	})
	return map[string]any{"response": map[string]any{"users": users}}
}

func (m *Manager) GetInboundUsers(request GetInboundUsersRequest) map[string]any {
	users := []map[string]any{}
	for _, user := range m.state.InboundUsers(request.Tag) {
		users = append(users, map[string]any{
			"email":    user.UserID,
			"username": user.UserID,
		})
	}
	return map[string]any{"response": map[string]any{"users": users}}
}

func (m *Manager) GetInboundUsersCount(request GetInboundUsersRequest) map[string]any {
	return map[string]any{"response": map[string]any{"count": len(m.state.InboundUsers(request.Tag))}}
}

func (m *Manager) AddUser(ctx context.Context, request AddUserRequest) map[string]any {
	if err := m.applyAddUserRequest(request); err != nil {
		return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
	}
	if err := m.restartCurrentCore(ctx); err != nil {
		return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
	}
	return map[string]any{"response": map[string]any{"success": true, "error": nil}}
}

func (m *Manager) AddUsers(ctx context.Context, request AddUsersRequest) map[string]any {
	if err := m.applyAddUsersRequest(request); err != nil {
		return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
	}
	if err := m.restartCurrentCore(ctx); err != nil {
		return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
	}
	return map[string]any{"response": map[string]any{"success": true, "error": nil}}
}

func (m *Manager) RemoveUser(ctx context.Context, request RemoveUserRequest) map[string]any {
	if err := m.removeUserEverywhere(request.Username); err != nil {
		return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
	}
	if err := m.restartCurrentCore(ctx); err != nil {
		return map[string]any{"response": map[string]any{"success": false, "error": err.Error()}}
	}
	return map[string]any{"response": map[string]any{"success": true, "error": nil}}
}

func (m *Manager) RemoveUsers(ctx context.Context, request RemoveUsersRequest) map[string]any {
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

func (m *Manager) DropUsersConnections(request DropUsersConnectionsRequest) map[string]any {
	for _, userID := range request.UserIDs {
		for _, item := range m.state.UserIPs(userID) {
			m.dropConnections(item.IP)
		}
	}
	return map[string]any{"response": map[string]any{"success": true}}
}

func (m *Manager) DropIPs(request DropIPsRequest) map[string]any {
	for _, ip := range request.IPs {
		m.dropConnections(ip)
	}
	return map[string]any{"response": map[string]any{"success": true}}
}

func (m *Manager) BlockIP(request VisionIPRequest) map[string]any {
	m.state.SetBlockedIP(request.IP, time.Time{})
	return map[string]any{"response": map[string]any{"success": true, "error": nil}}
}

func (m *Manager) UnblockIP(request VisionIPRequest) map[string]any {
	m.state.DeleteBlockedIP(request.IP)
	return map[string]any{"response": map[string]any{"success": true, "error": nil}}
}

func (m *Manager) SyncPlugin(ctx context.Context, request PluginSyncRequest) map[string]any {
	current := m.state.PluginState()
	if request.Plugin == nil {
		current = emptyPluginState()
		m.state.SetPluginState(current)
		if m.nftReady {
			_ = m.recreateNFTables(ctx)
		}
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
	m.state.SetPluginState(next)
	if m.nftReady {
		_ = m.recreateNFTables(ctx)
		_ = m.syncNFTState(ctx, next)
	}
	if changedTorrent {
		_ = m.restartCurrentCore(ctx)
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
			_ = m.nftDeleteElement(ctx, "torrent-blocker", ip)
			_ = m.nftDeleteElement(ctx, "ingress-filter-ip", ip)
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
	version := strings.TrimSpace(lines[0])
	return &version
}

func (m *Manager) applyAddUserRequest(request AddUserRequest) error {
	for _, item := range request.Data {
		if err := m.removeUserEverywhere(item.Username); err != nil {
			return err
		}
		if err := m.addUserToTag(item); err != nil {
			return err
		}
	}
	return nil
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
		{"add", "set", "inet", nftTableName, "ingress-filter-ip", "{", "type", "ipv4_addr;", "}"},
		{"add", "set", "inet", nftTableName, "egress-filter-ip", "{", "type", "ipv4_addr;", "}"},
		{"add", "set", "inet", nftTableName, "egress-filter-port", "{", "type", "inet_service;", "}"},
		{"add", "chain", "inet", nftTableName, "input", "{", "type", "filter", "hook", "input", "priority", "0;", "policy", "accept;", "}"},
		{"add", "chain", "inet", nftTableName, "output", "{", "type", "filter", "hook", "output", "priority", "0;", "policy", "accept;", "}"},
		{"add", "rule", "inet", nftTableName, "input", "ip", "saddr", "@ingress-filter-ip", "drop"},
		{"add", "rule", "inet", nftTableName, "input", "ip", "saddr", "@torrent-blocker", "drop"},
		{"add", "rule", "inet", nftTableName, "output", "ip", "daddr", "@egress-filter-ip", "drop"},
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
	if err := m.nftSyncSet(ctx, "ingress-filter-ip", pluginState.IngressBlocked); err != nil {
		return err
	}
	if err := m.nftSyncSet(ctx, "egress-filter-ip", pluginState.EgressBlockedIPs); err != nil {
		return err
	}
	if err := m.nftSyncPortSet(ctx, "egress-filter-port", pluginState.EgressBlockedPorts); err != nil {
		return err
	}
	return nil
}

func (m *Manager) blockIPWithTimeout(ctx context.Context, ip string, timeout int) error {
	until := time.Time{}
	if timeout > 0 {
		until = time.Now().Add(time.Duration(timeout) * time.Second)
	}
	m.state.SetBlockedIP(ip, until)
	if m.nftReady {
		args := []string{"add", "element", "inet", nftTableName, "torrent-blocker", "{", ip}
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

func (m *Manager) nftSyncSet(ctx context.Context, setName string, items []string) error {
	if err := m.runNft(ctx, "flush", "set", "inet", nftTableName, setName); err != nil {
		return err
	}
	filtered := make([]string, 0, len(items))
	for _, item := range items {
		if strings.Contains(item, ":") {
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

func applyXrayAPIConfig(config map[string]any, cfg config.Config, pluginState state.PluginState) map[string]any {
	if len(config) == 0 {
		return config
	}
	routing := ensureMap(config, "routing")
	rules := ensureSliceMap(routing, "rules")
	if pluginState.TorrentEnabled {
		webhookURL := fmt.Sprintf("/%s:/internal/webhook?token=%s", cfg.InternalSocketPath, cfg.InternalRESTToken)
		rule := map[string]any{
			"ruleTag": "torrent-blocker",
			"webhook": map[string]any{
				"url":           webhookURL,
				"deduplication": 5,
			},
		}
		rules = append([]map[string]any{rule}, rules...)
		routing["rules"] = toAnySlice(rules)
	}
	config["routing"] = routing
	return config
}

func addXrayUser(config map[string]any, item AddUserItem) error {
	for _, inbound := range asMapSlice(config["inbounds"]) {
		if stringValue(inbound["tag"]) != item.Tag {
			continue
		}
		settings := ensureMap(inbound, "settings")
		clients := ensureSliceMap(settings, "clients")
		client := map[string]any{"email": item.Username}
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
			if firstNonEmpty(stringValue(client["email"]), stringValue(client["name"])) == username {
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
		user := map[string]any{"name": item.Username}
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
			if firstNonEmpty(stringValue(user["name"]), stringValue(user["email"])) == username {
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
	items := asAnySlice(value)
	out := make([]string, 0, len(items))
	for _, item := range items {
		if typed, ok := item.(string); ok {
			out = append(out, typed)
		}
	}
	return out
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
