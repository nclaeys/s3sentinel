// Package proxy implements the core S3 proxy handler.
package proxy

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"

	"github.com/dataminded/s3sentinel/internal/auth"
	"github.com/dataminded/s3sentinel/internal/observability"
	"github.com/dataminded/s3sentinel/internal/opa"
	"github.com/dataminded/s3sentinel/internal/s3"
	"github.com/dataminded/s3sentinel/internal/sts"
)

// Config holds the proxy handler's dependencies and runtime settings.
type Config struct {
	// Backend S3 service
	BackendEndpoint string // e.g. https://s3.gra.io.cloud.ovh.net
	BackendRegion   string // e.g. gra
	BackendKey      string // service-account access key
	BackendSecret   string // service-account secret key

	// ProxyHost is used to detect virtual-hosted-style requests.
	// Leave empty to accept only path-style requests.
	ProxyHost string

	JWTValidator *auth.JWTValidator
	OPAClient    *opa.Client
	Metrics      *observability.Metrics
	Logger       *slog.Logger

	// STSTokenSecret is the HMAC key used to validate SessionToken JWTs issued
	// by the STS endpoint. When nil, session-token authentication is disabled
	// and the proxy only accepts Bearer / X-Auth-Token JWTs.
	STSTokenSecret []byte
}

// Handler is the main http.Handler implementing the proxy pipeline:
//
//	Extract JWT → Validate → Parse S3 action → OPA check → Re-sign → Forward
type Handler struct {
	cfg         Config
	backendURL  *url.URL
	credentials aws.Credentials
	signer      *v4.Signer
	httpClient  *http.Client
}

// NewHandler constructs a Handler. Panics if BackendEndpoint is not a valid URL.
func NewHandler(cfg Config) *Handler {
	backendURL, err := url.Parse(cfg.BackendEndpoint)
	if err != nil {
		panic(fmt.Sprintf("s3sentinel: invalid backend endpoint %q: %v", cfg.BackendEndpoint, err))
	}

	return &Handler{
		cfg:        cfg,
		backendURL: backendURL,
		credentials: aws.Credentials{
			AccessKeyID:     cfg.BackendKey,
			SecretAccessKey: cfg.BackendSecret,
		},
		signer: v4.NewSigner(),
		httpClient: &http.Client{
			Transport: &http.Transport{
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				// Preserve upstream response encoding; do not add Accept-Encoding.
				DisableCompression: true,
			},
		},
	}
}

// ServeHTTP implements http.Handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()

	// Wrap the writer so we can capture the status code for metrics.
	rw := &responseRecorder{ResponseWriter: w}

	// action is set once S3 parsing is done; used by the deferred metric.
	action := string(s3.ActionUnknown)

	defer func() {
		duration := time.Since(start).Seconds()
		status := strconv.Itoa(rw.statusCode())
		h.cfg.Metrics.RequestsTotal.WithLabelValues(action, status).Inc()
		h.cfg.Metrics.RequestDuration.WithLabelValues(action).Observe(duration)
	}()

	// ── 1. Authentication ────────────────────────────────────────────────────
	rawToken, sessionToken, err := extractAuth(r)
	if err != nil {
		h.cfg.Logger.Warn("auth: missing credentials",
			"remote", r.RemoteAddr,
			"method", r.Method,
			"path", r.URL.Path,
		)
		writeS3Error(rw, http.StatusUnauthorized, "InvalidToken", "bearer token or STS session token required")
		return
	}

	claims, err := h.getClaims(sessionToken, r, rw, ctx, rawToken)
	if err != nil {
		h.cfg.Logger.Warn("auth: failed to extract claims from token",
			"remote", r.RemoteAddr,
			"method", r.Method,
			"path", r.URL.Path,
			"error", err,
		)
		writeS3Error(rw, http.StatusUnauthorized, "InvalidToken", "failed to get claims from token")
		return
	}
	h.cfg.Metrics.JWTValidationsTotal.WithLabelValues("success").Inc()

	// ── 2. Parse S3 semantics ────────────────────────────────────────────────
	bucket, key := s3.ExtractBucketKey(r, h.cfg.ProxyHost)
	parsed := s3.Parse(r, bucket, key)
	action = string(parsed.Action) // now available to the deferred metric

	log := h.cfg.Logger.With(
		"principal", claims.Subject,
		"action", parsed.Action,
		"bucket", parsed.Bucket,
		"key", parsed.Key,
	)

	// ── 3. Authorisation (OPA) ───────────────────────────────────────────────
	opaStart := time.Now()
	allowed, err := h.cfg.OPAClient.Allow(ctx, opa.Input{
		Principal: claims.Subject,
		Email:     claims.Email,
		Groups:    claims.Groups,
		Action:    string(parsed.Action),
		Bucket:    parsed.Bucket,
		Key:       parsed.Key,
	})
	h.cfg.Metrics.OPAEvaluationDuration.Observe(time.Since(opaStart).Seconds())

	if err != nil {
		h.cfg.Metrics.OPAEvaluationsTotal.WithLabelValues("error").Inc()
		log.Error("opa: check failed", "error", err)
		writeS3Error(rw, http.StatusInternalServerError, "InternalError", "authorisation check failed")
		return
	}
	if !allowed {
		h.cfg.Metrics.OPAEvaluationsTotal.WithLabelValues("deny").Inc()
		log.Info("opa: denied")
		writeS3Error(rw, http.StatusForbidden, "AccessDenied", "access denied by policy")
		return
	}
	h.cfg.Metrics.OPAEvaluationsTotal.WithLabelValues("allow").Inc()

	log.Info("proxy: forwarding")

	// ── 4. Forward ───────────────────────────────────────────────────────────
	if err := h.forward(ctx, rw, r); err != nil {
		// Response headers may already be written; just log.
		log.Error("proxy: forward error", "error", err)
	}
}

func (h *Handler) getClaims(sessionToken string, r *http.Request, rw *responseRecorder, ctx context.Context, rawToken string) (*auth.Claims, error) {
	if sessionToken != "" {
		return h.processStsTokenFlow(r, rw, sessionToken)
	}
	return h.ProcessJwtTokenFlow(ctx, rawToken, r, rw)
}

func (h *Handler) ProcessJwtTokenFlow(ctx context.Context, rawToken string, r *http.Request, rw *responseRecorder) (*auth.Claims, error) {
	// Direct JWT flow: client passes an OIDC JWT as Bearer or X-Auth-Token.
	claims, err := h.cfg.JWTValidator.Validate(ctx, rawToken)
	if err != nil {
		h.cfg.Logger.Warn("auth: JWT validation failed",
			"remote", r.RemoteAddr,
			"error", err,
		)
		h.cfg.Metrics.JWTValidationsTotal.WithLabelValues("error").Inc()
		writeS3Error(rw, http.StatusUnauthorized, "InvalidToken", "JWT validation failed")
		return nil, nil
	}
	return claims, err
}

func (h *Handler) processStsTokenFlow(r *http.Request, rw *responseRecorder, sessionToken string) (*auth.Claims, error) {
	// STS flow: client exchanged an OIDC JWT for temporary credentials via
	// the STS endpoint; the SessionToken carries the identity as a signed JWT.
	if len(h.cfg.STSTokenSecret) == 0 {
		h.cfg.Logger.Warn("auth: session token presented but STS is not configured",
			"remote", r.RemoteAddr,
		)
		writeS3Error(rw, http.StatusUnauthorized, "InvalidToken", "STS session tokens are not enabled")
		return nil, nil
	}
	claims, err := sts.ValidateSessionToken(h.cfg.STSTokenSecret, sessionToken)
	if err != nil {
		h.cfg.Logger.Warn("auth: session token validation failed",
			"remote", r.RemoteAddr,
			"error", err,
		)
		h.cfg.Metrics.JWTValidationsTotal.WithLabelValues("error").Inc()
		writeS3Error(rw, http.StatusUnauthorized, "InvalidToken", "session token validation failed")
		return nil, nil
	}
	return claims, err
}

// forward re-signs the request with the backend service-account credentials
// and streams the response back to the client.
func (h *Handler) forward(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	// Build the backend target URL, preserving path and query string.
	target := *h.backendURL
	target.Path = r.URL.Path
	target.RawQuery = r.URL.RawQuery

	outReq, err := http.NewRequestWithContext(ctx, r.Method, target.String(), r.Body)
	if err != nil {
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "failed to build backend request")
		return fmt.Errorf("build backend request: %w", err)
	}

	// Copy safe headers; drop all client-supplied auth material.
	for k, vv := range r.Header {
		if isDroppedHeader(k) {
			continue
		}
		outReq.Header[k] = vv
	}

	// The backend expects its own hostname in Host.
	outReq.Host = h.backendURL.Host

	// Re-sign with the backend service-account credentials.
	//
	// "UNSIGNED-PAYLOAD" avoids buffering the entire request body for SHA-256
	// hashing, which is critical for large PutObject uploads.  All major
	// Ceph-based EU S3 providers (OVH, Scaleway, Exoscale, Hetzner) accept
	// this value; it is part of the AWS S3 specification for streaming uploads.
	if err := h.signer.SignHTTP(
		ctx,
		h.credentials,
		outReq,
		"UNSIGNED-PAYLOAD",
		"s3",
		h.cfg.BackendRegion,
		time.Now(),
	); err != nil {
		writeS3Error(w, http.StatusInternalServerError, "InternalError", "request signing failed")
		return fmt.Errorf("sign backend request: %w", err)
	}

	resp, err := h.httpClient.Do(outReq)
	if err != nil {
		writeS3Error(w, http.StatusBadGateway, "ServiceUnavailable", "backend unreachable")
		h.cfg.Metrics.BackendRequestsTotal.WithLabelValues("502").Inc()
		return fmt.Errorf("backend request: %w", err)
	}
	defer resp.Body.Close()

	h.cfg.Metrics.BackendRequestsTotal.WithLabelValues(strconv.Itoa(resp.StatusCode)).Inc()

	// Stream response headers + body back to the client.
	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	return err
}

// extractAuth returns the raw JWT or STS session token from the request.
// Precedence (first match wins):
//  1. Authorization: Bearer <token>     – standard OIDC / direct API use
//  2. X-Auth-Token: <token>             – S3 SDK compatibility: client uses fake
//     AWS credentials for SDK signing, but passes the real OIDC JWT here.
//  3. Authorization: AWS4-HMAC-SHA256 + X-Amz-Security-Token  – STS flow: client
//     exchanged its OIDC JWT for temporary credentials via the STS endpoint.
//
// rawToken and sessionToken are mutually exclusive; exactly one will be non-empty
// when err is nil.
func extractAuth(r *http.Request) (rawToken, sessionToken string, err error) {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer "), "", nil
	}
	if t := r.Header.Get("X-Auth-Token"); t != "" {
		return t, "", nil
	}
	if strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 ") {
		if st := r.Header.Get("X-Amz-Security-Token"); st != "" {
			return "", st, nil
		}
		return "", "", fmt.Errorf("AWS SigV4 request is missing X-Amz-Security-Token")
	}
	return "", "", fmt.Errorf("no bearer token in Authorization or X-Auth-Token")
}

// droppedHeaders lists canonical header names that must never be forwarded to
// the backend.  The SigV4 signer will add fresh values for the auth ones.
var droppedHeaders = map[string]bool{
	"Authorization":        true,
	"X-Amz-Security-Token": true,
	"X-Auth-Token":         true,
	// The signer writes a fresh x-amz-date; stale client values must be removed.
	"X-Amz-Date": true,
	// We use UNSIGNED-PAYLOAD; client-supplied hash values are irrelevant.
	"X-Amz-Content-Sha256": true,
}

func isDroppedHeader(key string) bool {
	return droppedHeaders[http.CanonicalHeaderKey(key)]
}

// writeS3Error writes a minimal S3-compatible XML error response.
// S3 clients expect this format even for non-2xx HTTP status codes.
func writeS3Error(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w,
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>%s</Code><Message>%s</Message></Error>",
		code, message,
	)
}

// responseRecorder wraps http.ResponseWriter to capture the HTTP status code
// written to the client, which is needed for request metrics.
// It also forwards the http.Flusher interface so streaming responses work.
type responseRecorder struct {
	http.ResponseWriter
	code    int
	written bool
}

func (r *responseRecorder) WriteHeader(code int) {
	if !r.written {
		r.code = code
		r.written = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.written {
		r.code = http.StatusOK
		r.written = true
	}
	return r.ResponseWriter.Write(b)
}

// statusCode returns the recorded status, defaulting to 200 if nothing was written.
func (r *responseRecorder) statusCode() int {
	if !r.written {
		return http.StatusOK
	}
	return r.code
}

// Flush forwards to the underlying ResponseWriter if it supports flushing.
func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
