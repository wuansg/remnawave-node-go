package forwarding

import (
	"bufio"
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
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	Capability    = "port_forwarding_v1"
	DNSCapability = "port_forwarding_dns_v1"
	TableName     = "remnanode_forward"
	maxRules      = 64
)

type Protocol string

const (
	ProtocolTCP    Protocol = "TCP"
	ProtocolUDP    Protocol = "UDP"
	ProtocolTCPUDP Protocol = "TCP_UDP"
)

type Rule struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Enabled       bool     `json:"enabled"`
	Protocol      Protocol `json:"protocol"`
	ListenPort    int      `json:"listenPort"`
	TargetAddress string   `json:"targetAddress"`
	TargetPort    int      `json:"targetPort"`
}

type Config struct {
	Enabled         bool   `json:"enabled"`
	ListenInterface string `json:"listenInterface"`
	Rules           []Rule `json:"rules"`
}

type SyncRequest struct {
	Config Config `json:"config"`
}

type Listener struct {
	Protocol Protocol `json:"protocol"`
	Port     int      `json:"port"`
	Source   string   `json:"source"`
}

type Counter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type DirectionCounters struct {
	Upload   Counter `json:"upload"`
	Download Counter `json:"download"`
}

type RuleStatus struct {
	ID                    string             `json:"id"`
	ResolvedTargetAddress string             `json:"resolvedTargetAddress,omitempty"`
	TCP                   *DirectionCounters `json:"tcp,omitempty"`
	UDP                   *DirectionCounters `json:"udp,omitempty"`
}

type Status struct {
	State                   string       `json:"state"`
	AppliedHash             string       `json:"appliedHash,omitempty"`
	AppliedAt               *time.Time   `json:"appliedAt,omitempty"`
	ResolvedListenInterface string       `json:"resolvedListenInterface,omitempty"`
	LastError               string       `json:"lastError,omitempty"`
	ForwardingEnabled       bool         `json:"forwardingEnabled"`
	FirewallForwardPolicy   string       `json:"firewallForwardPolicy,omitempty"`
	Rules                   []RuleStatus `json:"rules"`
}

type ConflictError struct {
	Protocol      Protocol `json:"protocol"`
	Port          int      `json:"port"`
	ConflictsWith string   `json:"conflictsWith"`
	Detail        string   `json:"detail,omitempty"`
}

func (e *ConflictError) Error() string {
	detail := e.ConflictsWith
	if e.Detail != "" {
		detail += ": " + e.Detail
	}
	return fmt.Sprintf("forwarding port conflict: %s/%d conflicts with %s", strings.ToLower(string(e.Protocol)), e.Port, detail)
}

func IsConflict(err error) bool {
	var conflict *ConflictError
	return errors.As(err, &conflict)
}

type persistedState struct {
	Config          Config            `json:"config"`
	AppliedHash     string            `json:"appliedHash"`
	AppliedAt       time.Time         `json:"appliedAt"`
	Interface       string            `json:"resolvedListenInterface"`
	ResolvedTargets map[string]string `json:"resolvedTargets,omitempty"`
}

type preparedConfig struct {
	config          Config
	iface           string
	routes          map[string]string
	resolvedTargets map[string]string
}

type lookupIPFunc func(context.Context, string, string) ([]net.IP, error)

type Service struct {
	mu          sync.Mutex
	path        string
	nodePort    int
	logger      *slog.Logger
	applied     Config
	appliedHash string
	appliedAt   *time.Time
	iface       string
	resolved    map[string]string
	lastError   string
	lookupIP    lookupIPFunc
}

func New(path string, nodePort int, logger *slog.Logger) *Service {
	return &Service{path: path, nodePort: nodePort, logger: logger, lookupIP: net.DefaultResolver.LookupIP}
}

func DefaultConfig() Config {
	return Config{Enabled: false, ListenInterface: "auto", Rules: []Rule{}}
}

func (s *Service) Restore(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	raw, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		s.lastError = err.Error()
		return err
	}
	var persisted persistedState
	if err := json.Unmarshal(raw, &persisted); err != nil {
		s.lastError = fmt.Sprintf("decode forwarding state: %v", err)
		return errors.New(s.lastError)
	}
	s.applied = normalizeConfig(persisted.Config)
	s.appliedHash = persisted.AppliedHash
	s.appliedAt = &persisted.AppliedAt
	s.iface = persisted.Interface
	s.resolved = persisted.ResolvedTargets

	if !s.applied.Enabled || enabledRuleCount(s.applied) == 0 {
		if err := s.reconcileHostFirewall(ctx, s.applied, "", nil); err != nil {
			s.lastError = fmt.Sprintf("restore host forwarding rules: %v", err)
			return errors.New(s.lastError)
		}
		return nil
	}
	if s.tableMatches(ctx, s.appliedHash) {
		prepared, err := s.validateLocked(ctx, s.applied, nil)
		if err != nil {
			s.lastError = fmt.Sprintf("validate restored forwarding rules: %v", err)
			return errors.New(s.lastError)
		}
		if !sameStringMap(s.resolved, prepared.resolvedTargets) {
			if err := s.applyPreparedLocked(ctx, s.applied, prepared, true); err != nil {
				s.lastError = fmt.Sprintf("refresh restored forwarding targets: %v", err)
				return errors.New(s.lastError)
			}
			return nil
		}
		if err := s.reconcileHostFirewall(ctx, prepared.config, prepared.iface, prepared.routes); err != nil {
			s.lastError = fmt.Sprintf("restore host forwarding rules: %v", err)
			return errors.New(s.lastError)
		}
		s.iface = prepared.iface
		s.resolved = prepared.resolvedTargets
		return nil
	}
	if err := s.applyLocked(ctx, s.applied, nil); err != nil {
		s.lastError = fmt.Sprintf("restore forwarding rules: %v", err)
		return errors.New(s.lastError)
	}
	return nil
}

func (s *Service) Validate(ctx context.Context, cfg Config, coreListeners []Listener) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.validateLocked(ctx, normalizeConfig(cfg), coreListeners)
	return err
}

func (s *Service) Sync(ctx context.Context, cfg Config, coreListeners []Listener) (Status, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cfg = normalizeConfig(cfg)
	if err := s.applyLocked(ctx, cfg, coreListeners); err != nil {
		s.lastError = err.Error()
		return s.statusLocked(ctx), err
	}
	s.lastError = ""
	return s.statusLocked(ctx), nil
}

func (s *Service) Status(ctx context.Context) Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statusLocked(ctx)
}

// RefreshDNS reapplies forwarding only when an enabled hostname resolves to a
// different IPv4 address. A transient DNS failure leaves the working rules in
// place and is returned to the caller for logging.
func (s *Service) RefreshDNS(ctx context.Context, coreListeners []Listener) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.applied.Enabled || enabledHostnameRuleCount(s.applied) == 0 {
		return nil
	}
	prepared, err := s.validateLocked(ctx, s.applied, coreListeners)
	if err != nil {
		return err
	}
	if sameStringMap(s.resolved, prepared.resolvedTargets) {
		return nil
	}
	if err := s.applyPreparedLocked(ctx, s.applied, prepared, true); err != nil {
		return err
	}
	s.lastError = ""
	return nil
}

func (s *Service) ValidateCoreConfig(coreType string, coreConfig map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.applied.Enabled {
		return nil
	}
	listeners := ExtractCoreListeners(coreType, coreConfig)
	for _, rule := range s.applied.Rules {
		if !rule.Enabled {
			continue
		}
		for _, listener := range listeners {
			if rule.ListenPort == listener.Port && protocolsOverlap(rule.Protocol, listener.Protocol) {
				return &ConflictError{Protocol: overlapProtocol(rule.Protocol, listener.Protocol), Port: rule.ListenPort, ConflictsWith: "CORE_INBOUND", Detail: listener.Source}
			}
		}
	}
	return nil
}

func (s *Service) applyLocked(ctx context.Context, cfg Config, coreListeners []Listener) error {
	prepared, err := s.validateLocked(ctx, cfg, coreListeners)
	if err != nil {
		return err
	}
	return s.applyPreparedLocked(ctx, cfg, prepared, false)
}

func (s *Service) applyPreparedLocked(ctx context.Context, cfg Config, prepared preparedConfig, skipConflicts bool) error {
	hash, err := configHash(cfg)
	if err != nil {
		return err
	}

	if !cfg.Enabled || enabledRuleCount(cfg) == 0 {
		if err := s.reconcileHostFirewall(ctx, cfg, "", nil); err != nil {
			return err
		}
		if err := s.deleteTable(ctx); err != nil {
			return err
		}
		now := time.Now().UTC()
		if err := s.persist(persistedState{Config: cfg, AppliedHash: hash, AppliedAt: now}); err != nil {
			return err
		}
		s.applied, s.appliedHash, s.appliedAt, s.iface, s.resolved = cfg, hash, &now, "", map[string]string{}
		return nil
	}

	if err := ensureIPv4Forwarding(); err != nil {
		return err
	}
	if !skipConflicts {
		if err := detectSocketConflicts(ctx, cfg, prepared.iface); err != nil {
			return err
		}
		if err := detectNFTConflicts(ctx, cfg); err != nil {
			return err
		}
	}
	script := renderRuleset(prepared.config, prepared.iface, prepared.routes, hash, s.tableExists(ctx))
	if err := runNFTScript(ctx, script, true); err != nil {
		return fmt.Errorf("validate nftables rules: %w", err)
	}
	if err := s.reconcileHostFirewall(ctx, prepared.config, prepared.iface, prepared.routes); err != nil {
		return fmt.Errorf("apply host firewall rules: %w", err)
	}
	if err := runNFTScript(ctx, script, false); err != nil {
		return fmt.Errorf("apply nftables rules: %w", err)
	}
	now := time.Now().UTC()
	if err := s.persist(persistedState{Config: cfg, AppliedHash: hash, AppliedAt: now, Interface: prepared.iface, ResolvedTargets: prepared.resolvedTargets}); err != nil {
		return err
	}
	s.applied, s.appliedHash, s.appliedAt, s.iface, s.resolved = cfg, hash, &now, prepared.iface, prepared.resolvedTargets
	return nil
}

func (s *Service) validateLocked(ctx context.Context, cfg Config, coreListeners []Listener) (preparedConfig, error) {
	result := preparedConfig{config: cfg, routes: map[string]string{}, resolvedTargets: map[string]string{}}
	if len(cfg.Rules) > maxRules {
		return result, fmt.Errorf("forwarding rules exceed maximum of %d", maxRules)
	}
	localAddresses := localIPv4Addresses()
	seenIDs := map[string]struct{}{}
	for i, rule := range cfg.Rules {
		if strings.TrimSpace(rule.ID) == "" {
			return result, fmt.Errorf("rule %d id is required", i+1)
		}
		if _, ok := seenIDs[rule.ID]; ok {
			return result, fmt.Errorf("duplicate forwarding rule id %q", rule.ID)
		}
		seenIDs[rule.ID] = struct{}{}
		if len(strings.TrimSpace(rule.Name)) < 1 || len(rule.Name) > 64 {
			return result, fmt.Errorf("rule %s name must be 1-64 characters", rule.ID)
		}
		if rule.Protocol != ProtocolTCP && rule.Protocol != ProtocolUDP && rule.Protocol != ProtocolTCPUDP {
			return result, fmt.Errorf("rule %s has unsupported protocol %q", rule.ID, rule.Protocol)
		}
		if rule.ListenPort < 1 || rule.ListenPort > 65535 || rule.TargetPort < 1 || rule.TargetPort > 65535 {
			return result, fmt.Errorf("rule %s port must be between 1 and 65535", rule.ID)
		}
		if !isIPv4Literal(rule.TargetAddress) && !isValidHostname(rule.TargetAddress) {
			return result, fmt.Errorf("rule %s targetAddress must be a routable IPv4 address or valid hostname", rule.ID)
		}
		if !rule.Enabled {
			continue
		}
		resolved, err := s.resolveTargetIPv4(ctx, rule.TargetAddress, s.resolved[rule.ID])
		if err != nil {
			return result, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		if _, local := localAddresses[resolved]; local {
			return result, fmt.Errorf("rule %s targetAddress resolves to this node (%s)", rule.ID, resolved)
		}
		result.config.Rules[i].TargetAddress = resolved
		result.resolvedTargets[rule.ID] = resolved
	}

	for i, left := range cfg.Rules {
		if !left.Enabled {
			continue
		}
		for _, right := range cfg.Rules[i+1:] {
			if right.Enabled && left.ListenPort == right.ListenPort && protocolsOverlap(left.Protocol, right.Protocol) {
				return result, &ConflictError{Protocol: overlapProtocol(left.Protocol, right.Protocol), Port: left.ListenPort, ConflictsWith: "FORWARDING_RULE", Detail: right.Name}
			}
		}
	}

	if !cfg.Enabled || enabledRuleCount(cfg) == 0 {
		return result, nil
	}
	iface, err := resolveListenInterface(ctx, cfg.ListenInterface)
	if err != nil {
		return result, err
	}
	result.iface = iface
	for _, rule := range cfg.Rules {
		if !rule.Enabled {
			continue
		}
		for _, listener := range coreListeners {
			if rule.ListenPort == listener.Port && protocolsOverlap(rule.Protocol, listener.Protocol) {
				return result, &ConflictError{Protocol: overlapProtocol(rule.Protocol, listener.Protocol), Port: rule.ListenPort, ConflictsWith: "CORE_INBOUND", Detail: listener.Source}
			}
		}
	}
	for _, rule := range result.config.Rules {
		if !rule.Enabled {
			continue
		}
		if _, ok := result.routes[rule.TargetAddress]; ok {
			continue
		}
		egress, err := resolveTargetInterface(ctx, rule.TargetAddress)
		if err != nil {
			return result, err
		}
		result.routes[rule.TargetAddress] = egress
	}
	return result, nil
}

func (s *Service) statusLocked(ctx context.Context) Status {
	state := "disabled"
	if s.applied.Enabled && enabledRuleCount(s.applied) > 0 {
		state = "applied"
		if !s.tableMatches(ctx, s.appliedHash) {
			state = "error"
		}
	}
	if s.lastError != "" {
		state = "error"
	}
	status := Status{
		State: state, AppliedHash: s.appliedHash, AppliedAt: s.appliedAt,
		ResolvedListenInterface: s.iface, LastError: s.lastError,
		ForwardingEnabled: readIPv4Forwarding(), FirewallForwardPolicy: firewallForwardPolicy(ctx),
		Rules: []RuleStatus{},
	}
	if status.State == "applied" && status.FirewallForwardPolicy == "drop" && !hostFirewallAllows(ctx, s.applied) {
		status.State = "degraded"
		status.LastError = "host FORWARD policy is drop; add explicit allow rules with remnanode-forward-host-allow comments for every forwarded flow"
	}
	counters := readCounters(ctx)
	for _, rule := range s.applied.Rules {
		if !rule.Enabled {
			continue
		}
		item := RuleStatus{ID: rule.ID, ResolvedTargetAddress: s.resolved[rule.ID]}
		if rule.Protocol == ProtocolTCP || rule.Protocol == ProtocolTCPUDP {
			value := directionCounters(counters, rule.ID, "tcp")
			item.TCP = &value
		}
		if rule.Protocol == ProtocolUDP || rule.Protocol == ProtocolTCPUDP {
			value := directionCounters(counters, rule.ID, "udp")
			item.UDP = &value
		}
		status.Rules = append(status.Rules, item)
	}
	return status
}

func (s *Service) persist(value persistedState) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".forwarding-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, s.path)
}

func (s *Service) tableExists(ctx context.Context) bool {
	return exec.CommandContext(ctx, "nft", "list", "table", "ip", TableName).Run() == nil
}

func (s *Service) tableMatches(ctx context.Context, hash string) bool {
	if hash == "" {
		return false
	}
	out, err := exec.CommandContext(ctx, "nft", "list", "table", "ip", TableName).CombinedOutput()
	return err == nil && strings.Contains(string(out), "remnanode-forward-config:"+hash)
}

func (s *Service) deleteTable(ctx context.Context) error {
	if !s.tableExists(ctx) {
		return nil
	}
	script := "delete table ip " + TableName + "\n"
	if err := runNFTScript(ctx, script, true); err != nil {
		return err
	}
	return runNFTScript(ctx, script, false)
}

func normalizeConfig(cfg Config) Config {
	if strings.TrimSpace(cfg.ListenInterface) == "" {
		cfg.ListenInterface = "auto"
	}
	if cfg.Rules == nil {
		cfg.Rules = []Rule{}
	}
	for i := range cfg.Rules {
		cfg.Rules[i].ID = strings.TrimSpace(cfg.Rules[i].ID)
		cfg.Rules[i].Name = strings.TrimSpace(cfg.Rules[i].Name)
		cfg.Rules[i].TargetAddress = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cfg.Rules[i].TargetAddress), "."))
	}
	return cfg
}

func enabledHostnameRuleCount(cfg Config) int {
	count := 0
	for _, rule := range cfg.Rules {
		if rule.Enabled && !isIPv4Literal(rule.TargetAddress) {
			count++
		}
	}
	return count
}

func (s *Service) resolveTargetIPv4(ctx context.Context, target, preferred string) (string, error) {
	if ip := net.ParseIP(target); ip != nil {
		if !isRoutableIPv4(ip) {
			return "", fmt.Errorf("targetAddress %q must be a routable IPv4 address", target)
		}
		return ip.String(), nil
	}
	if !isValidHostname(target) {
		return "", fmt.Errorf("targetAddress %q is not a valid hostname", target)
	}
	ips, err := s.lookupIP(ctx, "ip4", target)
	if err != nil {
		return "", fmt.Errorf("resolve targetAddress %q: %w", target, err)
	}
	resolved := make([]string, 0, len(ips))
	for _, ip := range ips {
		if isRoutableIPv4(ip) {
			value := ip.String()
			if value == preferred {
				return value, nil
			}
			resolved = append(resolved, value)
		}
	}
	if len(resolved) == 0 {
		return "", fmt.Errorf("targetAddress %q has no routable IPv4 address", target)
	}
	return resolved[0], nil
}

func isIPv4Literal(value string) bool {
	ip := net.ParseIP(value)
	return ip != nil && ip.To4() != nil
}

func isRoutableIPv4(ip net.IP) bool {
	return ip != nil && ip.To4() != nil && !ip.IsUnspecified() && !ip.IsLoopback() && !ip.IsMulticast() && !ip.IsLinkLocalUnicast() && !ip.Equal(net.IPv4bcast)
}

func isValidHostname(value string) bool {
	if len(value) == 0 || len(value) > 253 || strings.Contains(value, "..") || onlyDigitsAndDots(value) {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func onlyDigitsAndDots(value string) bool {
	for _, char := range value {
		if (char < '0' || char > '9') && char != '.' {
			return false
		}
	}
	return true
}

func sameStringMap(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func enabledRuleCount(cfg Config) int {
	count := 0
	for _, rule := range cfg.Rules {
		if rule.Enabled {
			count++
		}
	}
	return count
}

func configHash(cfg Config) (string, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func protocolsOverlap(left, right Protocol) bool {
	return left == ProtocolTCPUDP || right == ProtocolTCPUDP || left == right
}

func overlapProtocol(left, right Protocol) Protocol {
	if left == ProtocolTCPUDP {
		return right
	}
	return left
}

func localIPv4Addresses() map[string]struct{} {
	result := map[string]struct{}{}
	addrs, _ := net.InterfaceAddrs()
	for _, addr := range addrs {
		var ip net.IP
		switch value := addr.(type) {
		case *net.IPNet:
			ip = value.IP
		case *net.IPAddr:
			ip = value.IP
		}
		if ip != nil && ip.To4() != nil {
			result[ip.String()] = struct{}{}
		}
	}
	return result
}

func resolveListenInterface(ctx context.Context, configured string) (string, error) {
	if configured != "" && configured != "auto" {
		iface, err := net.InterfaceByName(configured)
		if err != nil {
			return "", fmt.Errorf("listen interface %q does not exist", configured)
		}
		if iface.Flags&net.FlagUp == 0 {
			return "", fmt.Errorf("listen interface %q is down", configured)
		}
		return configured, nil
	}
	out, err := exec.CommandContext(ctx, "ip", "-4", "route", "show", "default").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("resolve default IPv4 interface: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	fields := strings.Fields(string(out))
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			return fields[i+1], nil
		}
	}
	return "", errors.New("default IPv4 route has no interface")
}

func resolveTargetInterface(ctx context.Context, target string) (string, error) {
	out, err := exec.CommandContext(ctx, "ip", "-4", "route", "get", target).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("no IPv4 route to %s: %w (%s)", target, err, strings.TrimSpace(string(out)))
	}
	fields := strings.Fields(string(out))
	for i := 0; i+1 < len(fields); i++ {
		if fields[i] == "dev" {
			return fields[i+1], nil
		}
	}
	return "", fmt.Errorf("route to %s has no output interface", target)
}

func ensureIPv4Forwarding() error {
	if readIPv4Forwarding() {
		return nil
	}
	if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1\n"), 0o644); err != nil {
		return fmt.Errorf("net.ipv4.ip_forward is disabled; run 'sysctl -w net.ipv4.ip_forward=1' on the host: %w", err)
	}
	if !readIPv4Forwarding() {
		return errors.New("net.ipv4.ip_forward remains disabled after enabling it")
	}
	return nil
}

func readIPv4Forwarding() bool {
	raw, err := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	return err == nil && strings.TrimSpace(string(raw)) == "1"
}

func detectSocketConflicts(ctx context.Context, cfg Config, iface string) error {
	out, err := exec.CommandContext(ctx, "ss", "-H", "-lntup").CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect listening sockets: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		proto := Protocol(strings.ToUpper(fields[0]))
		if proto != ProtocolTCP && proto != ProtocolUDP {
			continue
		}
		address, port, ok := splitSocketAddress(fields[4])
		if !ok || isLoopbackAddress(address) {
			continue
		}
		for _, rule := range cfg.Rules {
			if rule.Enabled && rule.ListenPort == port && protocolsOverlap(rule.Protocol, proto) {
				detail := strings.Join(fields[5:], " ")
				return &ConflictError{Protocol: proto, Port: port, ConflictsWith: "NODE_SERVICE", Detail: detail}
			}
		}
	}
	return nil
}

func splitSocketAddress(value string) (string, int, bool) {
	idx := strings.LastIndex(value, ":")
	if idx < 0 || idx == len(value)-1 {
		return "", 0, false
	}
	port, err := strconv.Atoi(value[idx+1:])
	if err != nil {
		return "", 0, false
	}
	return strings.Trim(value[:idx], "[]"), port, true
}

func isLoopbackAddress(value string) bool {
	value = strings.Split(value, "%")[0]
	return value == "localhost" || strings.HasPrefix(value, "127.") || value == "::1"
}

var dnatRulePattern = regexp.MustCompile(`\b(tcp|udp)\s+dport\s+([0-9]+)\b.*\bdnat\b`)

func detectNFTConflicts(ctx context.Context, cfg Config) error {
	out, err := exec.CommandContext(ctx, "nft", "list", "ruleset").CombinedOutput()
	if err != nil {
		return fmt.Errorf("inspect nftables ruleset: %w (%s)", err, strings.TrimSpace(string(out)))
	}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	inManagedTable := false
	depth := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "table ") {
			inManagedTable = strings.HasPrefix(line, "table ip "+TableName+" ") || line == "table ip "+TableName+" {"
			depth = strings.Count(line, "{") - strings.Count(line, "}")
			continue
		}
		if inManagedTable {
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if depth <= 0 {
				inManagedTable = false
			}
			continue
		}
		match := dnatRulePattern.FindStringSubmatch(line)
		if len(match) != 3 {
			continue
		}
		port, _ := strconv.Atoi(match[2])
		proto := Protocol(strings.ToUpper(match[1]))
		for _, rule := range cfg.Rules {
			if rule.Enabled && rule.ListenPort == port && protocolsOverlap(rule.Protocol, proto) {
				return &ConflictError{Protocol: proto, Port: port, ConflictsWith: "NFT_RULE", Detail: line}
			}
		}
	}
	return scanner.Err()
}

func firewallForwardPolicy(ctx context.Context) string {
	out, err := exec.CommandContext(ctx, "nft", "list", "chain", "ip", "filter", "FORWARD").CombinedOutput()
	if err != nil {
		return "unknown"
	}
	text := string(out)
	if strings.Contains(text, "policy drop") {
		return "drop"
	}
	if strings.Contains(text, "policy accept") {
		return "accept"
	}
	return "unknown"
}

func hostFirewallAllows(ctx context.Context, cfg Config) bool {
	out, err := exec.CommandContext(ctx, "nft", "list", "ruleset").CombinedOutput()
	if err != nil {
		return false
	}
	ruleset := string(out)
	for _, rule := range cfg.Rules {
		if !rule.Enabled {
			continue
		}
		for _, protocol := range expandedProtocols(rule.Protocol) {
			for _, direction := range []string{"up", "down"} {
				comment := hostAllowComment(rule.ID, protocol, direction)
				if !strings.Contains(ruleset, comment) {
					return false
				}
			}
		}
	}
	return true
}

func hostAllowComment(id, protocol, direction string) string {
	return "remnanode-forward-host-allow:" + id + ":" + protocol + ":" + direction
}

func runNFTScript(ctx context.Context, script string, check bool) error {
	tmp, err := os.CreateTemp("", "remnanode-forward-*.nft")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.WriteString(script); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	args := []string{}
	if check {
		args = append(args, "-c")
	}
	args = append(args, "-f", name)
	out, err := exec.CommandContext(ctx, "nft", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s: %w (%s)", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

type nftJSON struct {
	NFTables []map[string]json.RawMessage `json:"nftables"`
}

type nftCounter struct {
	Name    string `json:"name"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

func readCounters(ctx context.Context) map[string]Counter {
	result := map[string]Counter{}
	out, err := exec.CommandContext(ctx, "nft", "-j", "list", "counters", "ip", TableName).CombinedOutput()
	if err != nil {
		return result
	}
	var doc nftJSON
	if json.Unmarshal(out, &doc) != nil {
		return result
	}
	for _, item := range doc.NFTables {
		raw, ok := item["counter"]
		if !ok {
			continue
		}
		var counter nftCounter
		if json.Unmarshal(raw, &counter) == nil {
			result[counter.Name] = Counter{Packets: counter.Packets, Bytes: counter.Bytes}
		}
	}
	return result
}

func directionCounters(values map[string]Counter, id, protocol string) DirectionCounters {
	prefix := counterPrefix(id, protocol)
	return DirectionCounters{Upload: values[prefix+"_up"], Download: values[prefix+"_down"]}
}

func counterPrefix(id, protocol string) string {
	digest := sha256.Sum256([]byte(id + ":" + protocol))
	return "rw_" + hex.EncodeToString(digest[:8])
}

func renderRuleset(cfg Config, ingress string, routes map[string]string, hash string, replace bool) string {
	var b strings.Builder
	if replace {
		fmt.Fprintf(&b, "delete table ip %s\n", TableName)
	}
	fmt.Fprintf(&b, "table ip %s {\n", TableName)
	fmt.Fprintf(&b, "  comment \"remnanode-forward-config:%s\"\n", hash)
	for _, rule := range cfg.Rules {
		if !rule.Enabled {
			continue
		}
		for _, proto := range expandedProtocols(rule.Protocol) {
			prefix := counterPrefix(rule.ID, proto)
			fmt.Fprintf(&b, "  counter %s_up {}\n", prefix)
			fmt.Fprintf(&b, "  counter %s_down {}\n", prefix)
		}
	}
	b.WriteString("  chain prerouting {\n    type nat hook prerouting priority dstnat; policy accept;\n")
	for _, rule := range cfg.Rules {
		if !rule.Enabled {
			continue
		}
		for _, proto := range expandedProtocols(rule.Protocol) {
			fmt.Fprintf(&b, "    iifname %q %s dport %d dnat to %s:%d comment %q\n", ingress, proto, rule.ListenPort, rule.TargetAddress, rule.TargetPort, "remnanode-forward:"+rule.ID+":"+proto+":dnat")
		}
	}
	b.WriteString("  }\n  chain postrouting {\n    type nat hook postrouting priority srcnat; policy accept;\n")
	type natKey struct {
		in, out, proto, addr string
		port                 int
	}
	keys := map[natKey]struct{}{}
	for _, rule := range cfg.Rules {
		if !rule.Enabled {
			continue
		}
		for _, proto := range expandedProtocols(rule.Protocol) {
			keys[natKey{ingress, routes[rule.TargetAddress], proto, rule.TargetAddress, rule.TargetPort}] = struct{}{}
		}
	}
	ordered := make([]natKey, 0, len(keys))
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Slice(ordered, func(i, j int) bool { return fmt.Sprint(ordered[i]) < fmt.Sprint(ordered[j]) })
	for _, key := range ordered {
		fmt.Fprintf(&b, "    iifname %q oifname %q ct status dnat ip daddr %s %s dport %d masquerade\n", key.in, key.out, key.addr, key.proto, key.port)
	}
	b.WriteString("  }\n  chain traffic {\n    type filter hook forward priority mangle; policy accept;\n")
	for _, rule := range cfg.Rules {
		if !rule.Enabled {
			continue
		}
		out := routes[rule.TargetAddress]
		for _, proto := range expandedProtocols(rule.Protocol) {
			prefix := counterPrefix(rule.ID, proto)
			fmt.Fprintf(&b, "    iifname %q oifname %q ip daddr %s %s dport %d counter name %s_up\n", ingress, out, rule.TargetAddress, proto, rule.TargetPort, prefix)
			fmt.Fprintf(&b, "    iifname %q oifname %q ip saddr %s %s sport %d counter name %s_down\n", out, ingress, rule.TargetAddress, proto, rule.TargetPort, prefix)
		}
	}
	b.WriteString("  }\n}\n")
	return b.String()
}

func expandedProtocols(protocol Protocol) []string {
	switch protocol {
	case ProtocolTCP:
		return []string{"tcp"}
	case ProtocolUDP:
		return []string{"udp"}
	default:
		return []string{"tcp", "udp"}
	}
}
