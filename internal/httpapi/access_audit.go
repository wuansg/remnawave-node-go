package httpapi

import (
	"github.com/remnawave/remnawave-node-go/internal/accessaudit"
	"net/http"
	"time"
)

func (s *Server) registerAccessAudit(mux *http.ServeMux) {
	for _, action := range []string{"config", "pull", "ack", "status"} {
		method := "POST"
		if action == "status" {
			method = "GET"
		}
		mux.HandleFunc(method+" /node/access-audit/"+action, s.requireJWT(func(w http.ResponseWriter, r *http.Request) {
			store := s.manager.AccessAudit()
			if store == nil {
				writeJSON(w, 501, map[string]any{"message": "Access audit is unavailable"})
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
			switch action {
			case "config":
				var c accessaudit.Config
				if !decodeJSON(w, r, &c) {
					return
				}
				if err := store.Configure(c, time.Now()); err != nil {
					writeJSON(w, 422, map[string]any{"message": err.Error()})
					return
				}
			case "pull":
				var b struct {
					Limit int `json:"limit"`
				}
				if !decodeJSON(w, r, &b) {
					return
				}
				batch, err := store.Pull(b.Limit)
				if err != nil {
					writeJSON(w, 500, map[string]any{"message": "Audit queue unavailable"})
					return
				}
				writeJSON(w, 200, map[string]any{"response": batch})
				return
			case "ack":
				var b struct {
					Generation      string `json:"generation"`
					ThroughSequence uint64 `json:"throughSequence"`
				}
				if !decodeJSON(w, r, &b) {
					return
				}
				if err := store.Ack(b.Generation, b.ThroughSequence); err != nil {
					writeJSON(w, 409, map[string]any{"message": err.Error()})
					return
				}
			}
			status, err := store.Status()
			if err != nil {
				writeJSON(w, 500, map[string]any{"message": "Audit status unavailable"})
				return
			}
			writeJSON(w, 200, map[string]any{"response": status})
		}))
	}
}
