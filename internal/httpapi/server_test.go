package httpapi

import (
	"bytes"
	"compress/gzip"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/remnawave/remnawave-node-go/internal/auth"
	"github.com/remnawave/remnawave-node-go/internal/benchmark"
	nodeapp "github.com/remnawave/remnawave-node-go/internal/node"
)

func TestDecodeRequestBodyPlainJSON(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest("POST", "/", bytes.NewBufferString(`{"plugin":null}`))

	payload, err := decodeRequestBody(req)
	if err != nil {
		t.Fatalf("decodeRequestBody() error = %v", err)
	}
	if string(payload) != `{"plugin":null}` {
		t.Fatalf("decodeRequestBody() = %q", string(payload))
	}
}

func TestDecodeJSONValidatesRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"ips":["not-an-ip"]}`))
	recorder := httptest.NewRecorder()
	var body nodeapp.DropIPsRequest
	if decodeJSON(recorder, req, &body) {
		t.Fatal("invalid request unexpectedly passed validation")
	}
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
	}
}

func TestRemovedCorePluginEndpoints(t *testing.T) {
	s := &Server{}
	mux := http.NewServeMux()
	s.registerPublic(mux)
	s.registerInternal(mux)
	for _, path := range []string{"/vision/block-ip", "/vision/unblock-ip", "/node/plugin/torrent-blocker/collect", "/internal/webhook"} {
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, recorder.Code)
		}
	}
}

func TestAccessAuditEndpointsRequireAuthentication(t *testing.T) {
	s := &Server{}
	mux := http.NewServeMux()
	s.registerPublic(mux)
	for _, request := range []struct{ method, path string }{
		{http.MethodPost, "/node/access-audit/config"},
		{http.MethodPost, "/node/access-audit/pull"},
		{http.MethodPost, "/node/access-audit/ack"},
		{http.MethodGet, "/node/access-audit/status"},
	} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(request.method, request.path, nil))
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%s: expected 401, got %d", request.path, response.Code)
		}
	}
}

func TestBenchmarkEndpointsRequireAuthentication(t *testing.T) {
	s := &Server{}
	mux := http.NewServeMux()
	s.registerPublic(mux)
	for _, request := range []struct{ method, path string }{
		{http.MethodPost, "/node/benchmarks/start"},
		{http.MethodPost, "/node/benchmarks/cancel"},
		{http.MethodGet, "/node/benchmarks/aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa"},
	} {
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, httptest.NewRequest(request.method, request.path, nil))
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("%s: expected 401, got %d", request.path, response.Code)
		}
	}
}

func TestBenchmarkAPIWithoutCore(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := auth.NewVerifier(string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&key.PublicKey)})))
	if err != nil {
		t.Fatal(err)
	}
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	claims, _ := json.Marshal(map[string]any{"exp": time.Now().Add(time.Minute).Unix()})
	input := header + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(input))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	token := input + "." + base64.RawURLEncoding.EncodeToString(signature)
	runner, err := benchmark.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer runner.Close()
	s := &Server{verifier: verifier, benchmarks: runner} // No core manager is needed.
	mux := http.NewServeMux()
	s.registerPublic(mux)
	request := benchmark.Request{ID: "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa", Kind: "NETWORK", Items: []string{"download"}, Family: "IPv4", Seconds: 1, BytesPerDirection: 1 << 20, Threads: 1, Targets: []benchmark.Target{{ID: "test", City: "Test", Provider: "Fixture", DownloadURL: "http://127.0.0.1/test"}}}
	call := func(method, path string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var data []byte
		if body != nil {
			data, _ = json.Marshal(body)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(data))
		req.Header.Set("Authorization", "Bearer "+token)
		response := httptest.NewRecorder()
		mux.ServeHTTP(response, req)
		return response
	}
	if response := call(http.MethodPost, "/node/benchmarks/start", request); response.Code != http.StatusOK {
		t.Fatal(response.Code, response.Body.String())
	}
	var response struct {
		Response benchmark.Job `json:"response"`
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		got := call(http.MethodGet, "/node/benchmarks/"+request.ID, nil)
		if got.Code != http.StatusOK {
			t.Fatal(got.Code)
		}
		if err = json.Unmarshal(got.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}
		if response.Response.Status != "RUNNING" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if len(response.Response.Results) != 1 || response.Response.Results[0].Status != "FAILED" {
		t.Fatal("private target was not rejected", response.Response)
	}
	if replay := call(http.MethodPost, "/node/benchmarks/start", request); replay.Code != http.StatusOK {
		t.Fatal("idempotent replay failed", replay.Code)
	}
	request.Seconds = 2
	if changed := call(http.MethodPost, "/node/benchmarks/start", request); changed.Code != http.StatusUnprocessableEntity {
		t.Fatal("changed request accepted", changed.Code)
	}
}

func TestCommonMiddlewareCompressesAndSecuresResponse(t *testing.T) {
	handler := commonHeaders(compressResponses(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true})
	})))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	if recorder.Header().Get("Content-Encoding") != "gzip" || recorder.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("unexpected middleware headers: %#v", recorder.Header())
	}
	reader, err := gzip.NewReader(recorder.Body)
	if err != nil {
		t.Fatalf("open gzip response: %v", err)
	}
	payload, _ := io.ReadAll(reader)
	if string(payload) != "{\"ok\":true}\n" {
		t.Fatalf("unexpected response: %q", payload)
	}
}

func TestDecodeRequestBodyZstdJSON(t *testing.T) {
	t.Parallel()

	var compressed bytes.Buffer
	encoder, err := zstd.NewWriter(&compressed)
	if err != nil {
		t.Fatalf("zstd.NewWriter() error = %v", err)
	}
	if _, err := encoder.Write([]byte(`{"plugin":null}`)); err != nil {
		t.Fatalf("encoder.Write() error = %v", err)
	}
	encoder.Close()

	req := httptest.NewRequest("POST", "/", &compressed)
	req.Header.Set("Content-Encoding", "zstd")

	payload, err := decodeRequestBody(req)
	if err != nil {
		t.Fatalf("decodeRequestBody() error = %v", err)
	}
	if string(payload) != `{"plugin":null}` {
		t.Fatalf("decodeRequestBody() = %q", string(payload))
	}
}
