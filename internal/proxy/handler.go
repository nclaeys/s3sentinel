package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
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

const emptyBodyHash = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

type Config struct {
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
type Handler struct {
	cfg         Config
	backendURL  *url.URL
	credentials aws.Credentials
	signer      *v4.Signer
	httpClient  *http.Client
}

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
				DisableCompression:    true,
			},
		},
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	start := time.Now()

	rw := &responseRecorder{ResponseWriter: w}

	action := string(s3.ActionUnknown)

	defer func() {
		duration := time.Since(start).Seconds()
		status := strconv.Itoa(rw.statusCode())
		h.cfg.Metrics.RequestsTotal.WithLabelValues(action, status).Inc()
		h.cfg.Metrics.RequestDuration.WithLabelValues(action).Observe(duration)
	}()

	claims, err := h.handleAuthentication(ctx, r)
	if err != nil {
		_ = writeS3Error(rw, http.StatusUnauthorized, "InvalidToken", fmt.Sprintf("failed to process the provided token due to %s", err.Error()))
		return
	}

	s3Request := s3.Parse(r, h.cfg.ProxyHost)
	action = string(s3Request.Action)

	err = h.authorizeRequest(ctx, claims, s3Request, rw)
	if err != nil {
		return
	}

	if err := h.forward(ctx, rw, r); err != nil {
		h.cfg.Logger.Error("proxy: forward error", "error", err, "request", r.URL, "principal", claims.Subject)
	}
}

func (h *Handler) authorizeRequest(ctx context.Context, claims *auth.Claims, s3Request s3.S3RequestContext, rw *responseRecorder) error {
	log := h.cfg.Logger.With(
		"principal", claims.Subject,
		"action", s3Request.Action,
		"bucket", s3Request.Bucket,
		"key", s3Request.Key,
	)

	opaStart := time.Now()
	allowed, err := h.cfg.OPAClient.Allow(ctx, opa.Input{
		Principal: claims.Subject,
		Email:     claims.Email,
		Groups:    claims.Groups,
		Action:    string(s3Request.Action),
		Bucket:    s3Request.Bucket,
		Key:       s3Request.Key,
	})
	h.cfg.Metrics.OPAEvaluationDuration.Observe(time.Since(opaStart).Seconds())

	if err != nil {
		h.cfg.Metrics.OPAEvaluationsTotal.WithLabelValues("error").Inc()
		log.Error("opa: check failed", "error", err)
		return writeS3Error(rw, http.StatusInternalServerError, "InternalError", "authorisation check failed")
	}
	if !allowed {
		h.cfg.Metrics.OPAEvaluationsTotal.WithLabelValues("deny").Inc()
		log.Info("opa: denied")
		return writeS3Error(rw, http.StatusForbidden, "AccessDenied", "access denied by policy")
	}
	h.cfg.Metrics.OPAEvaluationsTotal.WithLabelValues("allow").Inc()
	return nil
}

func (h *Handler) handleAuthentication(ctx context.Context, r *http.Request) (*auth.Claims, error) {
	rawToken, sessionToken, err := extractAuth(r)
	if err != nil {
		h.cfg.Logger.Warn("auth: missing credentials",
			"remote", r.RemoteAddr,
			"method", r.Method,
			"path", r.URL.Path,
		)
		return nil, err
	}

	if sessionToken != "" {
		return h.processStsTokenFlow(r, sessionToken)
	}
	return h.ProcessDirectJwtTokenFlow(ctx, rawToken, r)
}

func (h *Handler) ProcessDirectJwtTokenFlow(ctx context.Context, rawToken string, r *http.Request) (*auth.Claims, error) {
	claims, err := h.cfg.JWTValidator.Validate(ctx, rawToken)
	if err != nil {
		h.cfg.Logger.Warn("auth: JWT validation failed",
			"remote", r.RemoteAddr,
			"error", err,
		)
		h.cfg.Metrics.JWTValidationsTotal.WithLabelValues("error").Inc()
		return nil, err
	}
	h.cfg.Metrics.JWTValidationsTotal.WithLabelValues("success").Inc()
	return claims, err
}

func (h *Handler) processStsTokenFlow(r *http.Request, sessionToken string) (*auth.Claims, error) {
	if len(h.cfg.STSTokenSecret) == 0 {
		h.cfg.Logger.Warn("auth: session token presented but STS is not configured",
			"remote", r.RemoteAddr,
		)
		return nil, errors.New("STS session tokens are not enabled")
	}
	claims, err := sts.ValidateSessionToken(h.cfg.STSTokenSecret, sessionToken)
	if err != nil {
		h.cfg.Logger.Warn("auth: session token validation failed",
			"remote", r.RemoteAddr,
			"error", err,
		)
		h.cfg.Metrics.JWTValidationsTotal.WithLabelValues("error").Inc()
		return nil, err
	}
	h.cfg.Metrics.JWTValidationsTotal.WithLabelValues("success").Inc()
	return claims, nil
}

// forward re-signs the request with the backend blob storage credentials credentials
// and returnse the response back to the client.
func (h *Handler) forward(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	target := *h.backendURL
	target.Path = r.URL.Path
	target.RawQuery = r.URL.RawQuery
	target.RawPath = r.URL.EscapedPath()

	payloadHash, body, contentLength, err := resolvePayloadHash(r)
	if err != nil {
		return writeS3Error(w, http.StatusInternalServerError, "InternalError", "failed to hash request body")
	}

	outReq, err := http.NewRequestWithContext(ctx, r.Method, target.String(), body)
	if err != nil {
		return writeS3Error(w, http.StatusInternalServerError, "InternalError", "failed to build backend request")
	}
	outReq.ContentLength = contentLength
	outReq.Host = h.backendURL.Host
	outReq.Header.Set("Host", h.backendURL.Host)
	outReq.Header.Set("Content-Length", strconv.Itoa(int(contentLength)))
	outReq.Header.Set("X-Amz-Content-Sha256", payloadHash)

	// Copy safe headers; drop all client-supplied auth/signing material as that should be redone
	// This is needed because we need to keep request in tact, no manipulation after signing.
	for k, vv := range r.Header {
		if !isDroppedHeader(k) {
			outReq.Header[k] = vv
		}
	}

	if err := h.signer.SignHTTP(ctx, h.credentials, outReq, payloadHash, "s3", h.cfg.BackendRegion, time.Now()); err != nil {
		return writeS3Error(w, http.StatusInternalServerError, "InternalError", "request signing failed")
	}

	h.cfg.Logger.Debug("Forwarding request", "remote", r.RemoteAddr, "method", outReq.Method, "url", outReq.URL.String())
	h.cfg.Logger.Debug("forwarding request headers", "headers", outReq.Header)

	resp, err := h.httpClient.Do(outReq)
	if err != nil {
		h.cfg.Metrics.BackendRequestsTotal.WithLabelValues("502").Inc()
		return writeS3Error(w, http.StatusBadGateway, "ServiceUnavailable", "backend unreachable")
	}
	defer resp.Body.Close()

	h.cfg.Metrics.BackendRequestsTotal.WithLabelValues(strconv.Itoa(resp.StatusCode)).Inc()

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
//  1. Authorization: Bearer <token>: standard OIDC / direct API use
//  2. X-Auth-Token: <token>: S3 SDK compatibility: client uses fake
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

// droppedHeaders remove all headers related to authentication and signing of initial request
// because we will resign the request with the backend blob storage credentials
var droppedHeaders = map[string]bool{
	"Authorization":        true,
	"X-Amz-Security-Token": true,
	"X-Auth-Token":         true,
	"X-Amz-Date":           true,
	"X-Amz-Content-Sha256": true,

	// Host is set explicitly via outReq.Host; the client value points to the proxy, not the backend.
	"Host":           true,
	"Content-Length": true,
}

func isDroppedHeader(key string) bool {
	return droppedHeaders[http.CanonicalHeaderKey(key)]
}

// resolvePayloadHash determines the SigV4 payload hash to use when re-signing
// and, when necessary, buffers the body so the bytes can still be forwarded.
//
// Hash selection:
//   - Presigned URL (X-Amz-Signature in query string) → UNSIGNED-PAYLOAD, no buffering
//   - Client signals streaming or explicitly unsigned   → UNSIGNED-PAYLOAD, no buffering
//   - No body (GET, HEAD, DELETE …)                   → SHA-256 of empty string
//   - Regular request with body                         → buffer body, compute SHA-256
func resolvePayloadHash(r *http.Request) (hash string, body io.Reader, contentLength int64, err error) {
	// Presigned URL: the signature travels in the query string, not the
	// Authorization header. AWS and MinIO always accept UNSIGNED-PAYLOAD here.
	if r.URL.Query().Get("X-Amz-Signature") != "" {
		return "UNSIGNED-PAYLOAD", r.Body, r.ContentLength, nil
	}

	switch r.Header.Get("X-Amz-Content-Sha256") {
	case "UNSIGNED-PAYLOAD",
		"STREAMING-AWS4-HMAC-SHA256-PAYLOAD",
		"STREAMING-UNSIGNED-PAYLOAD-TRAILER":
		return "UNSIGNED-PAYLOAD", r.Body, r.ContentLength, nil
	}

	if r.Body == nil || r.Body == http.NoBody {
		return emptyBodyHash, nil, 0, nil
	}

	data, readErr := io.ReadAll(r.Body)
	r.Body.Close()
	if readErr != nil {
		return "", nil, 0, readErr
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), bytes.NewReader(data), int64(len(data)), nil
}

func writeS3Error(w http.ResponseWriter, status int, code, message string) error {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	_, err := fmt.Fprintf(w,
		"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Error><Code>%s</Code><Message>%s</Message></Error>",
		code, message,
	)
	if err != nil {
		return errors.New("failed to write S3 error as a response: " + err.Error())
	}
	return nil
}

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

func (r *responseRecorder) statusCode() int {
	if !r.written {
		return http.StatusOK
	}
	return r.code
}

func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}
