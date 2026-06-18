package httpapi

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/klauspost/compress/zstd"
	"github.com/remnawave/remnawave-node-go/internal/auth"
	"github.com/remnawave/remnawave-node-go/internal/config"
	nodeapp "github.com/remnawave/remnawave-node-go/internal/node"
)

const maxRequestBodySize = int64(1 << 30)

var ErrServerClosed = http.ErrServerClosed

type Server struct {
	cfg      config.Config
	logger   *slog.Logger
	verifier *auth.Verifier
	manager  *nodeapp.Manager

	public   *http.Server
	internal *http.Server
}

func NewServer(cfg config.Config, manager *nodeapp.Manager, logger *slog.Logger) (*Server, error) {
	verifier, err := auth.NewVerifier(cfg.NodePayload.JWTPublicKey)
	if err != nil {
		return nil, err
	}

	cert, err := tls.X509KeyPair([]byte(cfg.NodePayload.NodeCertPEM), []byte(cfg.NodePayload.NodeKeyPEM))
	if err != nil {
		return nil, fmt.Errorf("node TLS key pair is invalid: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM([]byte(cfg.NodePayload.CACertPEM)) {
		return nil, errors.New("CA certificate pool is invalid")
	}

	srv := &Server{
		cfg:      cfg,
		logger:   logger,
		verifier: verifier,
		manager:  manager,
	}

	publicMux := http.NewServeMux()
	srv.registerPublic(publicMux)

	internalMux := http.NewServeMux()
	srv.registerInternal(internalMux)

	srv.public = &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.NodePort),
		Handler:           commonHeaders(compressResponses(publicMux)),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    64 * 1024,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
			ClientCAs:    caPool,
			ClientAuth:   tls.RequireAndVerifyClientCert,
			MinVersion:   tls.VersionTLS12,
		},
	}
	srv.internal = &http.Server{Handler: commonHeaders(internalMux), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 64 * 1024}

	return srv, nil
}

func (s *Server) ListenAndServeTLS() error {
	return s.public.ListenAndServeTLS("", "")
}

func (s *Server) ListenAndServeInternal() error {
	if s.cfg.InternalSocketPath == "" {
		return errors.New("INTERNAL_SOCKET_PATH is required")
	}
	if err := os.MkdirAll(filepath.Dir(s.cfg.InternalSocketPath), 0o755); err != nil {
		return err
	}
	_ = os.Remove(s.cfg.InternalSocketPath)
	listener, err := net.Listen("unix", s.cfg.InternalSocketPath)
	if err != nil {
		return err
	}
	return s.internal.Serve(listener)
}

func (s *Server) Shutdown(ctx context.Context) error {
	_ = s.public.Shutdown(ctx)
	_ = s.internal.Shutdown(ctx)
	if s.cfg.InternalSocketPath != "" {
		_ = os.Remove(s.cfg.InternalSocketPath)
	}
	return nil
}

func (s *Server) registerPublic(mux *http.ServeMux) {
	mux.HandleFunc("POST /node/xray/start", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.StartRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.Start(r.Context(), body, clientIP(r)))
	}))
	mux.HandleFunc("GET /node/xray/stop", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.manager.Stop(r.Context()))
	}))
	mux.HandleFunc("GET /node/xray/healthcheck", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.manager.Healthcheck(r.Context()))
	}))

	mux.HandleFunc("POST /node/handler/add-user", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.AddUserRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.AddUser(r.Context(), body))
	}))
	mux.HandleFunc("POST /node/handler/get-inbound-users", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.GetInboundUsersRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.GetInboundUsers(r.Context(), body))
	}))
	mux.HandleFunc("POST /node/handler/remove-user", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.RemoveUserRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.RemoveUser(r.Context(), body))
	}))
	mux.HandleFunc("POST /node/handler/get-inbound-users-count", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.GetInboundUsersRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.GetInboundUsersCount(r.Context(), body))
	}))
	mux.HandleFunc("POST /node/handler/add-users", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.AddUsersRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.AddUsers(r.Context(), body))
	}))
	mux.HandleFunc("POST /node/handler/remove-users", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.RemoveUsersRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.RemoveUsers(r.Context(), body))
	}))
	mux.HandleFunc("POST /node/handler/drop-users-connections", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.DropUsersConnectionsRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.DropUsersConnections(r.Context(), body))
	}))
	mux.HandleFunc("POST /node/handler/drop-ips", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.DropIPsRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.DropIPs(body))
	}))

	mux.HandleFunc("POST /node/stats/get-user-online-status", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.GetUserOnlineStatusRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.GetUserOnlineStatus(r.Context(), body))
	}))
	mux.HandleFunc("GET /node/stats/get-system-stats", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.manager.GetSystemStats(r.Context()))
	}))
	mux.HandleFunc("POST /node/stats/get-users-stats", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.GetUsersStatsRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.GetUsersStats(r.Context(), body))
	}))
	mux.HandleFunc("POST /node/stats/get-inbound-stats", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.GetTagStatsRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.GetInboundStats(r.Context(), body))
	}))
	mux.HandleFunc("POST /node/stats/get-outbound-stats", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.GetTagStatsRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.GetOutboundStats(r.Context(), body))
	}))
	mux.HandleFunc("POST /node/stats/get-all-inbounds-stats", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.GetResetRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.GetAllInboundStats(r.Context(), body))
	}))
	mux.HandleFunc("POST /node/stats/get-all-outbounds-stats", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.GetResetRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.GetAllOutboundStats(r.Context(), body))
	}))
	mux.HandleFunc("POST /node/stats/get-combined-stats", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.GetResetRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.GetCombinedStats(r.Context(), body))
	}))
	mux.HandleFunc("POST /node/stats/get-user-ip-list", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.GetUserIPListRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.GetUserIPList(r.Context(), body))
	}))
	mux.HandleFunc("GET /node/stats/get-users-ip-list", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.manager.GetUsersIPList(r.Context()))
	}))

	mux.HandleFunc("POST /node/plugin/sync", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.PluginSyncRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.SyncPlugin(r.Context(), body))
	}))
	mux.HandleFunc("POST /node/plugin/torrent-blocker/collect", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.manager.CollectReports())
	}))
	mux.HandleFunc("POST /node/plugin/nftables/block-ips", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.BlockIPsRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.BlockIPs(r.Context(), body))
	}))
	mux.HandleFunc("POST /node/plugin/nftables/unblock-ips", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.UnblockIPsRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.UnblockIPs(r.Context(), body))
	}))
	mux.HandleFunc("POST /node/plugin/nftables/recreate-tables", s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.manager.RecreateTables(r.Context()))
	}))

	mux.HandleFunc("POST /vision/block-ip", func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.VisionIPRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.BlockIP(r.Context(), body))
	})
	mux.HandleFunc("POST /vision/unblock-ip", func(w http.ResponseWriter, r *http.Request) {
		var body nodeapp.VisionIPRequest
		if !decodeJSON(w, r, &body) {
			return
		}
		writeJSON(w, http.StatusOK, s.manager.UnblockIP(r.Context(), body))
	})
}

func (s *Server) registerInternal(mux *http.ServeMux) {
	mux.HandleFunc("GET /internal/get-config", s.requireInternalToken(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, s.manager.InternalConfig())
	}))
	mux.HandleFunc("POST /internal/webhook", s.requireInternalToken(func(w http.ResponseWriter, r *http.Request) {
		var body any
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			s.manager.HandleWebhook(r.Context(), body)
		}
		w.WriteHeader(http.StatusOK)
	}))
}

func (s *Server) requireJWT(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		header := r.Header.Get("Authorization")
		token := strings.TrimPrefix(header, "Bearer ")
		if token == header || token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"message": "missing bearer token"})
			return
		}
		if _, err := s.verifier.Verify(token); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]any{"message": err.Error()})
			return
		}
		next(w, r)
	}
}

func (s *Server) requireInternalToken(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" || token != s.cfg.InternalRESTToken {
			if hijacker, ok := w.(http.Hijacker); ok {
				if conn, _, err := hijacker.Hijack(); err == nil {
					_ = conn.Close()
				}
			}
			return
		}
		next(w, r)
	}
}

func decodeJSON[T any](w http.ResponseWriter, r *http.Request, out *T) bool {
	defer r.Body.Close()
	payload, err := decodeRequestBody(r)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "invalid JSON body"})
		return false
	}
	if err := json.Unmarshal(payload, out); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"message": "invalid JSON body"})
		return false
	}
	if value, ok := any(out).(interface{ Validate() error }); ok {
		if err := value.Validate(); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"message": err.Error()})
			return false
		}
	}
	return true
}

func decodeRequestBody(r *http.Request) ([]byte, error) {
	reader := io.Reader(r.Body)
	encoding := strings.TrimSpace(strings.ToLower(r.Header.Get("Content-Encoding")))
	switch encoding {
	case "", "identity":
	case "zstd":
		decoder, err := zstd.NewReader(r.Body)
		if err != nil {
			return nil, err
		}
		defer decoder.Close()
		reader = decoder
	default:
		return nil, fmt.Errorf("unsupported content encoding: %s", encoding)
	}

	payload, err := io.ReadAll(io.LimitReader(reader, maxRequestBodySize+1))
	if err != nil {
		return nil, err
	}
	if int64(len(payload)) > maxRequestBodySize {
		return nil, fmt.Errorf("request body exceeds %d bytes", maxRequestBodySize)
	}
	if len(bytes.TrimSpace(payload)) == 0 {
		return nil, io.EOF
	}
	return payload, nil
}

type gzipResponseWriter struct {
	http.ResponseWriter
	writer *gzip.Writer
}

func (w gzipResponseWriter) Write(payload []byte) (int, error) {
	return w.writer.Write(payload)
}

func compressResponses(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Accept-Encoding")
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		writer := gzip.NewWriter(w)
		defer writer.Close()
		next.ServeHTTP(gzipResponseWriter{ResponseWriter: w, writer: writer}, r)
	})
}

func commonHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func clientIP(r *http.Request) string {
	value := r.RemoteAddr
	if host, _, err := net.SplitHostPort(value); err == nil {
		return host
	}
	return value
}
