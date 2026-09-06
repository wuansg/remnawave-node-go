package node

import (
	"context"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	cfgpkg "github.com/remnawave/remnawave-node-go/internal/config"
)

func TestSingBoxUserConnectionProviderUsesClashAPI(t *testing.T) {
	provider := singBoxUserConnectionProvider{
		apiBaseURL: "http://sing-box.test",
		apiSecret:  "test-secret",
		httpClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				if got := r.Header.Get("Authorization"); got != "Bearer test-secret" {
					t.Fatalf("expected bearer token, got %q", got)
				}
				return newHTTPResponse(http.StatusOK, `{"connections":[{"id":"a","metadata":{"sourceIP":"8.8.8.8","user":"2.rwib.QW55VExT"}},{"id":"b","metadata":{"sourceIP":"1.1.1.1","user":"2.rwib.U0JfVHJvamFuX1dT"}},{"id":"c","metadata":{"sourceIP":"9.9.9.9","user":"5.rwib.QW55VExT"}}]}`), nil
			}),
		},
	}

	items, err := provider.UserIPList(context.Background(), "2")
	if err != nil {
		t.Fatalf("expected sing-box user ip list to succeed: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 sing-box user IPs, got %d", len(items))
	}

	allUsers, err := provider.UsersIPList(context.Background())
	if err != nil {
		t.Fatalf("expected sing-box users ip list to succeed: %v", err)
	}
	if len(allUsers) != 2 {
		t.Fatalf("expected 2 sing-box users, got %d", len(allUsers))
	}
	if allUsers["5"][0].IP != "9.9.9.9" {
		t.Fatalf("unexpected sing-box users response: %#v", allUsers)
	}
}

func TestSingBoxUserConnectionProviderClosesMatchedConnections(t *testing.T) {
	var deleted []string
	provider := singBoxUserConnectionProvider{
		apiBaseURL: "http://sing-box.test",
		httpClient: &http.Client{
			Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				switch {
				case r.Method == http.MethodGet && r.URL.Path == "/connections":
					return newHTTPResponse(http.StatusOK, `{"connections":[{"id":"a","metadata":{"sourceIP":"8.8.8.8","user":"2"}},{"id":"b","metadata":{"sourceIP":"1.1.1.1","user":"2"}},{"id":"c","metadata":{"sourceIP":"9.9.9.9","user":"5"}}]}`), nil
				case r.Method == http.MethodDelete:
					deleted = append(deleted, r.URL.Path)
					return newHTTPResponse(http.StatusNoContent, ""), nil
				default:
					t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
					return nil, nil
				}
			}),
		},
	}

	if err := provider.CloseUserConnections(context.Background(), "2"); err != nil {
		t.Fatalf("expected sing-box close user connections to succeed: %v", err)
	}
	if !slices.Equal(deleted, []string{"/connections/a", "/connections/b"}) {
		t.Fatalf("unexpected deleted connection ids: %#v", deleted)
	}
}

func TestApplySingBoxAPIConfigEnablesClashAPI(t *testing.T) {
	config := map[string]any{
		"inbounds": []any{
			map[string]any{"tag": "anytls", "type": "anytls"},
		},
	}

	out := applySingBoxAPIConfig(config, cfgpkg.Config{
		SingBoxAPIPort:      61001,
		SingBoxV2RayAPIPort: 61002,
		InternalRESTToken:   "test-secret",
	})

	experimental := ensureConfigMap(out["experimental"])
	clashAPI := ensureConfigMap(experimental["clash_api"])
	if stringValue(clashAPI["external_controller"]) != "127.0.0.1:61001" {
		t.Fatalf("unexpected sing-box clash api listen address: %#v", clashAPI)
	}
	if stringValue(clashAPI["secret"]) != "test-secret" {
		t.Fatalf("expected sing-box clash api secret to be set, got %#v", clashAPI)
	}
	v2rayAPI := ensureConfigMap(experimental["v2ray_api"])
	if stringValue(v2rayAPI["listen"]) != "127.0.0.1:61002" {
		t.Fatalf("unexpected sing-box v2ray api address: %#v", v2rayAPI)
	}
}

func TestApplySingBoxAPIConfigRemovesUnmanagedClashAPISecret(t *testing.T) {
	config := map[string]any{
		"experimental": map[string]any{
			"clash_api": map[string]any{"secret": "panel-secret"},
		},
	}

	out := applySingBoxAPIConfig(config, cfgpkg.Config{SingBoxAPIPort: 61001})

	experimental := ensureConfigMap(out["experimental"])
	clashAPI := ensureConfigMap(experimental["clash_api"])
	if _, ok := clashAPI["secret"]; ok {
		t.Fatalf("expected unmanaged sing-box clash api secret to be removed, got %#v", clashAPI)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func newHTTPResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}
