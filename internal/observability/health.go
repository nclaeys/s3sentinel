package observability

import (
	"context"
	"encoding/json"
	"net/http"
	"time"
)

// Checker is implemented by any component that can report its own health.
// The OPA client and JWT validator both satisfy this interface.
type Checker interface {
	Check(ctx context.Context) error
}

// NewHealthHandler returns a liveness handler that always responds 200 OK.
// If the process can handle HTTP traffic it is considered alive.
func NewHealthHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"}) //nolint:errcheck,gosec
	})
}

// NewReadyHandler returns a readiness handler that calls every named Checker.
// It responds 200 when all checks pass, 503 when any check fails.
// Each check is given a 5-second deadline.
//
// Example response (all healthy):
//
//	{"jwks":{"status":"ok"},"opa":{"status":"ok"}}
//
// Example response (OPA unreachable):
//
//	{"jwks":{"status":"ok"},"opa":{"status":"error","error":"connection refused"}}
func NewReadyHandler(checkers map[string]Checker) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		type result struct {
			Status string `json:"status"`
			Error  string `json:"error,omitempty"`
		}

		results := make(map[string]result, len(checkers))
		allOK := true

		for name, c := range checkers {
			if err := c.Check(ctx); err != nil {
				results[name] = result{Status: "error", Error: err.Error()}
				allOK = false
			} else {
				results[name] = result{Status: "ok"}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		if allOK {
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(results) //nolint:errcheck,gosec
	})
}
