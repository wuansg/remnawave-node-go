package state

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/remnawave/remnawave-node-go/internal/statname"
)

type CoreType string

const (
	CoreTypeSingBox CoreType = "SING_BOX"
)

type InboundHash struct {
	Tag        string `json:"tag"`
	Hash       string `json:"hash"`
	UsersCount int    `json:"usersCount"`
}

type StartHashes struct {
	EmptyConfig string        `json:"emptyConfig"`
	Inbounds    []InboundHash `json:"inbounds"`
}

type InboundUser struct {
	UserID   string `json:"userId"`
	Protocol string `json:"protocol"`
	Tag      string `json:"tag"`
}

type SeenIP struct {
	IP       string    `json:"ip"`
	LastSeen time.Time `json:"lastSeen"`
}

type PluginMeta struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

type TorrentReport struct {
	ActionReport map[string]any `json:"actionReport"`
	CoreReport   any            `json:"xrayReport"`
}

type PluginState struct {
	ConfigHash              string
	ActivePlugin            *PluginMeta
	ConnectionDropWhitelist map[string]struct{}
	IngressBlocked          []string
	EgressBlockedBaseIPs    []string
	EgressBlockedIPs        []string
	EgressBlockedDomains    []string
	EgressBlockedPorts      []int
	TorrentEnabled          bool
	TorrentDuration         int
	TorrentIgnoredIPs       map[string]struct{}
	TorrentIgnoredUsers     map[string]struct{}
	TorrentIncludeRuleTags  map[string]struct{}
	TorrentReports          []TorrentReport
}

type Runtime struct {
	mu sync.RWMutex

	singBoxConfig map[string]any
	running       CoreType

	nodeVer        string
	singBoxVersion *string
	singBoxOnline  bool

	lastHashes  StartHashes
	hashesDirty bool

	inboundUsers map[string][]InboundUser
	inboundKinds map[string]string
	userIPs      map[string][]SeenIP
	blockedIPs   map[string]time.Time
	plugin       PluginState
}

func New(nodeVersion string) *Runtime {
	return &Runtime{
		singBoxConfig: map[string]any{},
		nodeVer:       nodeVersion,
		inboundUsers:  map[string][]InboundUser{},
		inboundKinds:  map[string]string{},
		userIPs:       map[string][]SeenIP{},
		blockedIPs:    map[string]time.Time{},
		plugin: PluginState{
			ConnectionDropWhitelist: map[string]struct{}{},
			TorrentIgnoredIPs:       map[string]struct{}{},
			TorrentIgnoredUsers:     map[string]struct{}{},
			TorrentIncludeRuleTags:  map[string]struct{}{},
		},
	}
}

func (r *Runtime) SingBoxConfig() map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneMap(r.singBoxConfig)
}

func (r *Runtime) CurrentConfig() map[string]any {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return cloneMap(r.singBoxConfig)
}

func (r *Runtime) SetSingBoxConfig(config map[string]any) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.singBoxConfig = cloneMap(config)
	if r.running == CoreTypeSingBox {
		r.reindexLocked(r.singBoxConfig)
	}
}

func (r *Runtime) SetRunningCore(core CoreType) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running = core
	if core == CoreTypeSingBox {
		r.reindexLocked(r.singBoxConfig)
	} else {
		r.inboundUsers = map[string][]InboundUser{}
		r.inboundKinds = map[string]string{}
	}
}

func (r *Runtime) RunningCore() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return string(r.running)
}

func (r *Runtime) RunningCoreType() CoreType {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.running
}

func (r *Runtime) NodeVersion() string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.nodeVer
}

func (r *Runtime) SetCoreVersion(singBoxVersion *string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.singBoxVersion = clonePtr(singBoxVersion)
}

func (r *Runtime) CoreVersion() *string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return clonePtr(r.singBoxVersion)
}

func (r *Runtime) SetOnlineStatus(singBoxOnline bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.singBoxOnline = singBoxOnline
}

func (r *Runtime) OnlineStatus() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.singBoxOnline
}

func (r *Runtime) SetLastHashes(hashes StartHashes) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastHashes = hashes
	r.hashesDirty = false
}

func (r *Runtime) ShouldRestart(incoming StartHashes) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.hashesDirty {
		return true
	}
	if r.lastHashes.EmptyConfig == "" {
		return true
	}
	if r.lastHashes.EmptyConfig != incoming.EmptyConfig {
		return true
	}
	if len(r.lastHashes.Inbounds) != len(incoming.Inbounds) {
		return true
	}
	current := make(map[string]InboundHash, len(r.lastHashes.Inbounds))
	for _, item := range r.lastHashes.Inbounds {
		current[item.Tag] = item
	}
	for _, item := range incoming.Inbounds {
		existing, ok := current[item.Tag]
		if !ok || existing.Hash != item.Hash || existing.UsersCount != item.UsersCount {
			return true
		}
	}
	return false
}

func (r *Runtime) MarkHashesDirty() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.hashesDirty = true
}

func (r *Runtime) InboundUsers(tag string) []InboundUser {
	r.mu.RLock()
	defer r.mu.RUnlock()
	users := r.inboundUsers[tag]
	out := make([]InboundUser, len(users))
	copy(out, users)
	return out
}

func (r *Runtime) InboundUsersMap() map[string][]InboundUser {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string][]InboundUser, len(r.inboundUsers))
	for key, users := range r.inboundUsers {
		cloned := make([]InboundUser, len(users))
		copy(cloned, users)
		out[key] = cloned
	}
	return out
}

func (r *Runtime) InboundProtocol(tag string) string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.inboundKinds[tag]
}

func (r *Runtime) RecordUserIP(userID, ip string, seenAt time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	list := r.userIPs[userID]
	filtered := list[:0]
	for _, item := range list {
		if item.IP == ip {
			continue
		}
		filtered = append(filtered, item)
	}
	filtered = append(filtered, SeenIP{IP: ip, LastSeen: seenAt})
	sort.Slice(filtered, func(i, j int) bool {
		return filtered[i].LastSeen.After(filtered[j].LastSeen)
	})
	r.userIPs[userID] = filtered
}

func (r *Runtime) UserIPs(userID string) []SeenIP {
	r.mu.RLock()
	defer r.mu.RUnlock()
	list := r.userIPs[userID]
	out := make([]SeenIP, len(list))
	copy(out, list)
	return out
}

func (r *Runtime) AllUserIPs() map[string][]SeenIP {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string][]SeenIP, len(r.userIPs))
	for key, list := range r.userIPs {
		cloned := make([]SeenIP, len(list))
		copy(cloned, list)
		out[key] = cloned
	}
	return out
}

func (r *Runtime) SetBlockedIP(ip string, until time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.blockedIPs[ip] = until
}

func (r *Runtime) DeleteBlockedIP(ip string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.blockedIPs, ip)
}

func (r *Runtime) BlockedIPs() map[string]time.Time {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]time.Time, len(r.blockedIPs))
	for key, value := range r.blockedIPs {
		out[key] = value
	}
	return out
}

func (r *Runtime) PluginState() PluginState {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.plugin.clone()
}

func (r *Runtime) SetPluginState(state PluginState) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.plugin = state.clone()
}

func (r *Runtime) AddTorrentReport(report TorrentReport) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.plugin.TorrentReports = append(r.plugin.TorrentReports, report)
}

func (r *Runtime) FlushTorrentReports() []TorrentReport {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]TorrentReport, len(r.plugin.TorrentReports))
	copy(out, r.plugin.TorrentReports)
	r.plugin.TorrentReports = nil
	return out
}

func (r *Runtime) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.running = ""
	r.singBoxOnline = false
	r.inboundUsers = map[string][]InboundUser{}
	r.inboundKinds = map[string]string{}
	r.userIPs = map[string][]SeenIP{}
}

func (r *Runtime) reindexLocked(config map[string]any) {
	r.inboundUsers = map[string][]InboundUser{}
	r.inboundKinds = map[string]string{}
	extractSingBoxInbounds(config, r.inboundUsers, r.inboundKinds)
}

func extractSingBoxInbounds(config map[string]any, target map[string][]InboundUser, kinds map[string]string) {
	for _, inbound := range asObjectSlice(config["inbounds"]) {
		tag := asString(inbound["tag"])
		protocol := normalizeSingBoxType(asString(inbound["type"]))
		if tag == "" || protocol == "" {
			continue
		}
		kinds[tag] = protocol
		for _, user := range asObjectSlice(inbound["users"]) {
			userID := firstNonEmpty(asString(user["name"]), asString(user["email"]))
			if userID == "" {
				continue
			}
			target[tag] = append(target[tag], InboundUser{
				UserID:   statname.UserID(userID),
				Protocol: protocol,
				Tag:      tag,
			})
		}
	}
}

func ConfigHash(value any) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:])
}

func normalizeSingBoxType(value string) string {
	if strings.EqualFold(value, "hysteria2") || strings.EqualFold(value, "hy2") {
		return "hysteria2"
	}
	return value
}

func cloneMap(input map[string]any) map[string]any {
	if input == nil {
		return map[string]any{}
	}
	encoded, err := json.Marshal(input)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(encoded, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func clonePtr(value *string) *string {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

func (p PluginState) clone() PluginState {
	out := PluginState{
		ConfigHash:              p.ConfigHash,
		IngressBlocked:          append([]string(nil), p.IngressBlocked...),
		EgressBlockedBaseIPs:    append([]string(nil), p.EgressBlockedBaseIPs...),
		EgressBlockedIPs:        append([]string(nil), p.EgressBlockedIPs...),
		EgressBlockedDomains:    append([]string(nil), p.EgressBlockedDomains...),
		EgressBlockedPorts:      append([]int(nil), p.EgressBlockedPorts...),
		TorrentEnabled:          p.TorrentEnabled,
		TorrentDuration:         p.TorrentDuration,
		TorrentReports:          append([]TorrentReport(nil), p.TorrentReports...),
		ConnectionDropWhitelist: cloneStringSet(p.ConnectionDropWhitelist),
		TorrentIgnoredIPs:       cloneStringSet(p.TorrentIgnoredIPs),
		TorrentIgnoredUsers:     cloneStringSet(p.TorrentIgnoredUsers),
		TorrentIncludeRuleTags:  cloneStringSet(p.TorrentIncludeRuleTags),
	}
	if p.ActivePlugin != nil {
		copied := *p.ActivePlugin
		out.ActivePlugin = &copied
	}
	return out
}

func cloneStringSet(input map[string]struct{}) map[string]struct{} {
	out := make(map[string]struct{}, len(input))
	for key := range input {
		out[key] = struct{}{}
	}
	return out
}

func asMap(value any) map[string]any {
	if typed, ok := value.(map[string]any); ok {
		return typed
	}
	return map[string]any{}
}

func asObjectSlice(value any) []map[string]any {
	raw, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		if typed, ok := item.(map[string]any); ok {
			out = append(out, typed)
		}
	}
	return out
}

func asString(value any) string {
	typed, _ := value.(string)
	return typed
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
