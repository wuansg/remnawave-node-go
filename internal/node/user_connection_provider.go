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
	"strings"
	"time"

	"github.com/remnawave/remnawave-node-go/internal/state"
	"github.com/remnawave/remnawave-node-go/internal/statname"
)

var (
	ErrUserConnectionStatsUnsupported = errors.New("user connection stats are unsupported for the running core")
)

type UserConnectionProvider interface {
	UserOnlineStatus(ctx context.Context, userID string) (bool, error)
	UserIPList(ctx context.Context, userID string) ([]state.SeenIP, error)
	UsersIPList(ctx context.Context) (map[string][]state.SeenIP, error)
}

type UserConnectionCloser interface {
	CloseUserConnections(ctx context.Context, userID string) error
}

func newUserConnectionProvider(singBoxAPIPort int, apiSecret string) UserConnectionProvider {
	return newSingBoxUserConnectionProvider(singBoxAPIPort, apiSecret)
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
		return statname.UserID(connection.Metadata.User) == userID && connection.Metadata.SourceIP != ""
	})
}

func groupSingBoxConnectionsByUser(connections []singBoxConnection) map[string][]singBoxConnection {
	grouped := make(map[string][]singBoxConnection)
	for _, connection := range connections {
		if connection.Metadata.User == "" || connection.Metadata.SourceIP == "" {
			continue
		}
		userID := statname.UserID(connection.Metadata.User)
		if userID == "" {
			continue
		}
		grouped[userID] = append(grouped[userID], connection)
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

func runCombinedOutput(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

func sortSeenIPs(items []state.SeenIP) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].LastSeen.Equal(items[j].LastSeen) {
			return items[i].IP < items[j].IP
		}
		return items[i].LastSeen.After(items[j].LastSeen)
	})
}
