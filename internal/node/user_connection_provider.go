package node

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/remnawave/remnawave-node-go/internal/state"
)

var (
	ErrUserConnectionStatsUnsupported = errors.New("user connection stats are unsupported for the running core")
	errXrayStatsNotFound              = errors.New("xray user connection stats not found")
	errXrayStatsAPIUnavailable        = errors.New("xray stats api is unavailable")
)

type UserConnectionProvider interface {
	UserOnlineStatus(ctx context.Context, userID string) (bool, error)
	UserIPList(ctx context.Context, userID string) ([]state.SeenIP, error)
	UsersIPList(ctx context.Context) (map[string][]state.SeenIP, error)
}

type UserConnectionCloser interface {
	CloseUserConnections(ctx context.Context, userID string) error
}

type execCommandFunc func(ctx context.Context, name string, args ...string) ([]byte, error)

func newUserConnectionProvider(xrayAPIPort, singBoxAPIPort int, apiSecret string, runtimeState *state.Runtime) UserConnectionProvider {
	switch runtimeState.RunningCoreType() {
	case state.CoreTypeSingBox:
		return newSingBoxUserConnectionProvider(singBoxAPIPort, apiSecret)
	case state.CoreTypeXRAY, "":
		return newXrayUserConnectionProvider(xrayAPIPort, runtimeState)
	default:
		return singBoxUserConnectionProvider{}
	}
}

func newXrayUserConnectionProvider(xrayAPIPort int, runtimeState *state.Runtime) xrayUserConnectionProvider {
	provider := xrayUserConnectionProvider{
		runtimeState: runtimeState,
		runCommand:   runCombinedOutput,
		commandPath:  xrayAPICommandPath(),
	}
	if xrayAPIPort > 0 {
		provider.apiServerAddr = fmt.Sprintf("127.0.0.1:%d", xrayAPIPort)
	}
	return provider
}

type xrayUserConnectionProvider struct {
	runtimeState  *state.Runtime
	apiServerAddr string
	runCommand    execCommandFunc
	commandPath   string
}

func (p xrayUserConnectionProvider) UserOnlineStatus(ctx context.Context, userID string) (bool, error) {
	items, err := p.UserIPList(ctx, userID)
	if err != nil {
		return p.runtimeOnlineStatus(userID), err
	}
	return len(items) > 0, nil
}

func (p xrayUserConnectionProvider) UserIPList(ctx context.Context, userID string) ([]state.SeenIP, error) {
	if p.canUseAPI() {
		items, err := p.userIPListFromAPI(ctx, userID)
		switch {
		case err == nil:
			return items, nil
		case errors.Is(err, errXrayStatsNotFound):
			return []state.SeenIP{}, nil
		case errors.Is(err, errXrayStatsAPIUnavailable):
			return p.runtimeState.UserIPs(userID), nil
		default:
			return nil, err
		}
	}
	return p.runtimeState.UserIPs(userID), nil
}

func (p xrayUserConnectionProvider) UsersIPList(ctx context.Context) (map[string][]state.SeenIP, error) {
	if p.canUseAPI() {
		items, err := p.usersIPListFromAPI(ctx)
		switch {
		case err == nil:
			return items, nil
		case errors.Is(err, errXrayStatsAPIUnavailable):
			return p.runtimeState.AllUserIPs(), nil
		default:
			return nil, err
		}
	}
	return p.runtimeState.AllUserIPs(), nil
}

func (p xrayUserConnectionProvider) canUseAPI() bool {
	return p.apiServerAddr != "" && p.runCommand != nil
}

func (p xrayUserConnectionProvider) userIPListFromAPI(ctx context.Context, userID string) ([]state.SeenIP, error) {
	output, err := p.runXrayAPICommand(ctx, "api", "statsonlineiplist", "--server="+p.apiServerAddr, "-email", userID)
	if err != nil {
		return nil, err
	}

	var response xrayOnlineIPListResponse
	if err := json.Unmarshal(output, &response); err != nil {
		return nil, fmt.Errorf("decode xray online ip list: %w", err)
	}

	items := make([]state.SeenIP, 0, len(response.IPs))
	for ip, lastSeen := range response.IPs {
		items = append(items, state.SeenIP{
			IP:       ip,
			LastSeen: time.Unix(int64(lastSeen), 0),
		})
	}
	sortSeenIPs(items)
	return items, nil
}

func (p xrayUserConnectionProvider) usersIPListFromAPI(ctx context.Context) (map[string][]state.SeenIP, error) {
	output, err := p.runXrayAPICommand(ctx, "api", "statsgetallonlineusers", "--server="+p.apiServerAddr)
	if err != nil {
		return nil, err
	}

	var response xrayAllOnlineUsersResponse
	if err := json.Unmarshal(output, &response); err != nil {
		return nil, fmt.Errorf("decode xray online users list: %w", err)
	}

	items := make(map[string][]state.SeenIP, len(response.Users))
	for _, userID := range response.Users {
		seenIPs, err := p.userIPListFromAPI(ctx, userID)
		if errors.Is(err, errXrayStatsNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if len(seenIPs) == 0 {
			continue
		}
		items[userID] = seenIPs
	}

	return items, nil
}

func (p xrayUserConnectionProvider) runXrayAPICommand(ctx context.Context, args ...string) ([]byte, error) {
	binary := p.commandPath
	if binary == "" {
		binary = xrayAPICommandPath()
	}
	if binary == "" {
		return nil, errXrayStatsAPIUnavailable
	}

	callCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	output, err := p.runCommand(callCtx, binary, args...)
	if err == nil {
		return output, nil
	}

	message := strings.TrimSpace(string(output))
	if message == "" {
		message = err.Error()
	}

	switch {
	case strings.Contains(strings.ToLower(message), "not found"):
		return nil, errXrayStatsNotFound
	case strings.Contains(strings.ToLower(message), "failed to dial"),
		strings.Contains(strings.ToLower(message), "connection refused"),
		strings.Contains(strings.ToLower(message), "context deadline exceeded"):
		return nil, errXrayStatsAPIUnavailable
	default:
		return nil, fmt.Errorf("run xray api command %q: %w (%s)", strings.Join(args, " "), err, message)
	}
}

func (p xrayUserConnectionProvider) runtimeOnlineStatus(userID string) bool {
	now := time.Now()
	for _, item := range p.runtimeState.UserIPs(userID) {
		if now.Sub(item.LastSeen) <= 10*time.Minute {
			return true
		}
	}
	return false
}

func newSingBoxUserConnectionProvider(apiPort int, apiSecret string) singBoxUserConnectionProvider {
	provider := singBoxUserConnectionProvider{
		apiSecret: apiSecret,
		httpClient: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
	if apiPort > 0 {
		provider.apiBaseURL = fmt.Sprintf("http://127.0.0.1:%d", apiPort)
	}
	return provider
}

type singBoxUserConnectionProvider struct {
	apiBaseURL string
	apiSecret  string
	httpClient *http.Client
}

func (p singBoxUserConnectionProvider) UserOnlineStatus(ctx context.Context, userID string) (bool, error) {
	items, err := p.UserIPList(ctx, userID)
	if err != nil {
		return false, err
	}
	return len(items) > 0, nil
}

func (p singBoxUserConnectionProvider) UserIPList(ctx context.Context, userID string) ([]state.SeenIP, error) {
	if !p.canUseAPI() {
		return nil, ErrUserConnectionStatsUnsupported
	}

	connections, err := p.connections(ctx)
	if err != nil {
		return nil, err
	}
	return formatSingBoxSeenIPs(filterSingBoxConnectionsByUser(connections, userID)), nil
}

func (p singBoxUserConnectionProvider) UsersIPList(ctx context.Context) (map[string][]state.SeenIP, error) {
	if !p.canUseAPI() {
		return nil, ErrUserConnectionStatsUnsupported
	}

	connections, err := p.connections(ctx)
	if err != nil {
		return nil, err
	}

	grouped := make(map[string][]state.SeenIP)
	for userID, items := range groupSingBoxConnectionsByUser(connections) {
		grouped[userID] = formatSingBoxSeenIPs(items)
	}
	return grouped, nil
}

func (p singBoxUserConnectionProvider) CloseUserConnections(ctx context.Context, userID string) error {
	if !p.canUseAPI() {
		return ErrUserConnectionStatsUnsupported
	}

	connections, err := p.connections(ctx)
	if err != nil {
		return err
	}

	for _, connection := range filterSingBoxConnectionsByUser(connections, userID) {
		if connection.ID == "" {
			continue
		}
		if err := p.deleteConnection(ctx, connection.ID); err != nil {
			return err
		}
	}
	return nil
}

func (p singBoxUserConnectionProvider) canUseAPI() bool {
	return p.apiBaseURL != "" && p.httpClient != nil
}

func (p singBoxUserConnectionProvider) connections(ctx context.Context) ([]singBoxConnection, error) {
	body, err := p.doJSONRequest(ctx, http.MethodGet, "/connections")
	if err != nil {
		return nil, err
	}

	var response singBoxConnectionsResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return nil, fmt.Errorf("decode sing-box connections: %w", err)
	}
	return response.Connections, nil
}

func (p singBoxUserConnectionProvider) deleteConnection(ctx context.Context, id string) error {
	_, err := p.doJSONRequest(ctx, http.MethodDelete, "/connections/"+id)
	return err
}

func (p singBoxUserConnectionProvider) doJSONRequest(ctx context.Context, method, path string) ([]byte, error) {
	callCtx := ctx
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		callCtx, cancel = context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
	}

	request, err := http.NewRequestWithContext(callCtx, method, p.apiBaseURL+path, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("Accept", "application/json")
	if p.apiSecret != "" {
		request.Header.Set("Authorization", "Bearer "+p.apiSecret)
	}

	response, err := p.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("request sing-box %s %s: %w", method, path, err)
	}
	defer response.Body.Close()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("request sing-box %s %s failed: %s", method, path, strings.TrimSpace(string(body)))
	}
	return body, nil
}

type singBoxConnectionsResponse struct {
	Connections []singBoxConnection `json:"connections"`
}

type singBoxConnection struct {
	ID       string `json:"id"`
	Metadata struct {
		SourceIP string `json:"sourceIP"`
		User     string `json:"user"`
	} `json:"metadata"`
}

func filterSingBoxConnectionsByUser(connections []singBoxConnection, userID string) []singBoxConnection {
	return commonFilterSingBoxConnections(connections, func(connection singBoxConnection) bool {
		return connection.Metadata.User == userID && connection.Metadata.SourceIP != ""
	})
}

func groupSingBoxConnectionsByUser(connections []singBoxConnection) map[string][]singBoxConnection {
	grouped := make(map[string][]singBoxConnection)
	for _, connection := range connections {
		if connection.Metadata.User == "" || connection.Metadata.SourceIP == "" {
			continue
		}
		grouped[connection.Metadata.User] = append(grouped[connection.Metadata.User], connection)
	}
	return grouped
}

func formatSingBoxSeenIPs(connections []singBoxConnection) []state.SeenIP {
	byIP := make(map[string]state.SeenIP)
	now := time.Now()
	for _, connection := range connections {
		current := byIP[connection.Metadata.SourceIP]
		current.IP = connection.Metadata.SourceIP
		current.LastSeen = now
		byIP[connection.Metadata.SourceIP] = current
	}

	items := make([]state.SeenIP, 0, len(byIP))
	for _, item := range byIP {
		items = append(items, item)
	}
	sortSeenIPs(items)
	return items
}

func commonFilterSingBoxConnections(connections []singBoxConnection, predicate func(singBoxConnection) bool) []singBoxConnection {
	filtered := make([]singBoxConnection, 0, len(connections))
	for _, connection := range connections {
		if predicate(connection) {
			filtered = append(filtered, connection)
		}
	}
	return filtered
}

type xrayOnlineIPListResponse struct {
	Name string               `json:"name"`
	IPs  map[string]jsonInt64 `json:"ips"`
}

type xrayAllOnlineUsersResponse struct {
	Users []string `json:"users"`
}

type jsonInt64 int64

func (v *jsonInt64) UnmarshalJSON(data []byte) error {
	raw := strings.TrimSpace(string(data))
	raw = strings.Trim(raw, "\"")
	if raw == "" || raw == "null" {
		*v = 0
		return nil
	}
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil {
		return err
	}
	*v = jsonInt64(value)
	return nil
}

func runCombinedOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func xrayAPICommandPath() string {
	for _, candidate := range []string{"/usr/local/bin/rw-core", "rw-core", "/usr/local/bin/xray", "xray"} {
		if commandExists(candidate) {
			return candidate
		}
	}
	return ""
}

func sortSeenIPs(items []state.SeenIP) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastSeen.Equal(items[j].LastSeen) {
			return items[i].IP < items[j].IP
		}
		return items[i].LastSeen.After(items[j].LastSeen)
	})
}
