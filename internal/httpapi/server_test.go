package httpapi

import (
	"bytes"
	"net/http/httptest"
	"testing"

	"github.com/klauspost/compress/zstd"
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
