package httpapi

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/klauspost/compress/zstd"
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
	req := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(`{"ip":"not-an-ip"}`))
	recorder := httptest.NewRecorder()
	var body nodeapp.VisionIPRequest
	if decodeJSON(recorder, req, &body) {
		t.Fatal("invalid request unexpectedly passed validation")
	}
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadRequest)
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
