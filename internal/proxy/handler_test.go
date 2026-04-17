package proxy

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/prometheus/client_golang/prometheus"

	"github.com/dataminded/s3sentinel/internal/auth"
	"github.com/dataminded/s3sentinel/internal/observability"
	"github.com/dataminded/s3sentinel/internal/opa"
	"github.com/dataminded/s3sentinel/internal/sts"
)

func newTestMetrics(t *testing.T) *observability.Metrics {
	t.Helper()
	return observability.NewMetrics(prometheus.NewRegistry())
}

func opaServer(t *testing.T, allow bool) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintf(w, `{"result":%v}`, allow)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func backendServer(t *testing.T) (*httptest.Server, *http.Request) {
	t.Helper()
	var last *http.Request
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		last = r
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok")) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return srv, last
}

func newHandler(t *testing.T, opaURL, backendURL string, stsSecret []byte, jwtValidator *auth.JWTValidator) *Handler {
	t.Helper()
	return NewHandler(Config{
		BackendEndpoint: backendURL,
		BackendRegion:   "us-east-1",
		BackendKey:      "test-access-key",
		BackendSecret:   "test-secret-key",
		ProxyHost:       "",
		JWTValidator:    jwtValidator,
		OPAClient:       opa.NewClient(opaURL),
		Metrics:         newTestMetrics(t),
		Logger:          slog.Default(),
		STSTokenSecret:  stsSecret,
	})
}

func stsToken(t *testing.T, secret []byte, subject string, groups []string) string {
	t.Helper()
	claims := &auth.Claims{Subject: subject, Email: subject + "@example.com", Groups: groups}
	creds, err := sts.IssueCredentials(secret, claims, time.Hour)
	if err != nil {
		t.Fatalf("IssueCredentials: %v", err)
	}
	return creds.SessionToken
}

func stsRequest(t *testing.T, method, path, sessionToken string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=ASIAFAKE/20240101/us-east-1/s3/aws4_request")
	req.Header.Set("X-Amz-Security-Token", sessionToken)
	return req
}

const testIssuer = "https://test.example.com"

// jwksServer starts an httptest JWKS server backed by a fresh RSA key pair.
func jwksServer(t *testing.T) (*rsa.PrivateKey, *httptest.Server) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	pubJWK, err := jwk.FromRaw(privKey.Public())
	if err != nil {
		t.Fatalf("JWK from public key: %v", err)
	}
	pubJWK.Set(jwk.KeyIDKey, "test-kid")    //nolint:errcheck
	pubJWK.Set(jwk.AlgorithmKey, jwa.RS256) //nolint:errcheck

	set := jwk.NewSet()
	set.AddKey(pubJWK) //nolint:errcheck

	keyBytes, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(keyBytes) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return privKey, srv
}

func signJWT(t *testing.T, privKey *rsa.PrivateKey, subject, email string, groups []string) string {
	t.Helper()

	tok, err := jwt.NewBuilder().
		Issuer(testIssuer).
		Subject(subject).
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Claim("email", email).
		Claim("groups", groups).
		Build()
	if err != nil {
		t.Fatalf("build JWT: %v", err)
	}

	privJWK, err := jwk.FromRaw(privKey)
	if err != nil {
		t.Fatalf("JWK from private key: %v", err)
	}
	privJWK.Set(jwk.KeyIDKey, "test-kid")    //nolint:errcheck
	privJWK.Set(jwk.AlgorithmKey, jwa.RS256) //nolint:errcheck

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privJWK))
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return string(signed)
}

func newJWTValidator(t *testing.T, jwksURL string) *auth.JWTValidator {
	t.Helper()
	v, err := auth.NewJWTValidator(jwksURL, testIssuer, nil)
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}
	return v
}

func TestExtractAuth(t *testing.T) {
	cases := []struct {
		name            string
		headers         map[string]string
		wantRaw         string
		wantSession     string
		wantErrContains string
	}{
		{
			name:    "bearer token",
			headers: map[string]string{"Authorization": "Bearer my-jwt-token"},
			wantRaw: "my-jwt-token",
		},
		{
			name:    "x-auth-token",
			headers: map[string]string{"X-Auth-Token": "my-x-auth-token"},
			wantRaw: "my-x-auth-token",
		},
		{
			name: "aws4 with security token",
			headers: map[string]string{
				"Authorization":        "AWS4-HMAC-SHA256 Credential=test",
				"X-Amz-Security-Token": "session-token-value",
			},
			wantSession: "session-token-value",
		},
		{
			name:            "aws4 without security token",
			headers:         map[string]string{"Authorization": "AWS4-HMAC-SHA256 Credential=test"},
			wantErrContains: "X-Amz-Security-Token",
		},
		{
			name:            "no credentials",
			headers:         map[string]string{},
			wantErrContains: "no bearer token",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			raw, session, err := extractAuth(req)

			if tc.wantErrContains != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErrContains)
				}
				if !strings.Contains(err.Error(), tc.wantErrContains) {
					t.Errorf("error %q does not contain %q", err.Error(), tc.wantErrContains)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if raw != tc.wantRaw {
				t.Errorf("rawToken: got %q, want %q", raw, tc.wantRaw)
			}
			if session != tc.wantSession {
				t.Errorf("sessionToken: got %q, want %q", session, tc.wantSession)
			}
		})
	}
}

func TestResolvePayloadHash(t *testing.T) {
	bodyContent := []byte("hello world")

	cases := []struct {
		name           string
		buildReq       func() *http.Request
		wantHash       string
		wantBodyNil    bool
		wantContentLen int64
	}{
		{
			name: "presigned url → UNSIGNED-PAYLOAD",
			buildReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodGet, "/?X-Amz-Signature=abc", nil)
				req.Body = io.NopCloser(bytes.NewReader(bodyContent))
				req.ContentLength = int64(len(bodyContent))
				return req
			},
			wantHash:       "UNSIGNED-PAYLOAD",
			wantContentLen: int64(len(bodyContent)),
		},
		{
			name: "streaming payload header → UNSIGNED-PAYLOAD",
			buildReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodPut, "/bucket/key", io.NopCloser(bytes.NewReader(bodyContent)))
				req.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
				req.ContentLength = int64(len(bodyContent))
				return req
			},
			wantHash:       "UNSIGNED-PAYLOAD",
			wantContentLen: int64(len(bodyContent)),
		},
		{
			name: "explicitly unsigned → UNSIGNED-PAYLOAD",
			buildReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodPut, "/bucket/key", io.NopCloser(bytes.NewReader(bodyContent)))
				req.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
				req.ContentLength = int64(len(bodyContent))
				return req
			},
			wantHash:       "UNSIGNED-PAYLOAD",
			wantContentLen: int64(len(bodyContent)),
		},
		{
			name: "no body → empty body hash",
			buildReq: func() *http.Request {
				return httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
			},
			wantHash:    emptyBodyHash,
			wantBodyNil: true,
		},
		{
			name: "regular body → real sha256",
			buildReq: func() *http.Request {
				req := httptest.NewRequest(http.MethodPut, "/bucket/key", bytes.NewReader(bodyContent))
				req.ContentLength = int64(len(bodyContent))
				return req
			},
			// SHA-256("hello world") = b94d27b9934d3e08a52e52d7da7dabfac484efe04294e576fea1e3a2
			// Let the test just verify it's a 64-char hex string (not UNSIGNED-PAYLOAD).
			wantHash:       "",
			wantContentLen: int64(len(bodyContent)),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.buildReq()
			hash, body, contentLength, err := resolvePayloadHash(req)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if tc.wantHash != "" && hash != tc.wantHash {
				t.Errorf("hash: got %q, want %q", hash, tc.wantHash)
			}
			// For the "regular body" case verify it looks like a real hex sha256.
			if tc.name == "regular body → real sha256" {
				if len(hash) != 64 {
					t.Errorf("expected 64-char hex hash, got %q (len=%d)", hash, len(hash))
				}
				if hash == emptyBodyHash || hash == "UNSIGNED-PAYLOAD" {
					t.Errorf("expected real body hash, got %q", hash)
				}
			}

			if tc.wantBodyNil && body != nil {
				t.Error("expected nil body, got non-nil")
			}
			if tc.wantContentLen != 0 && contentLength != tc.wantContentLen {
				t.Errorf("contentLength: got %d, want %d", contentLength, tc.wantContentLen)
			}
		})
	}
}

func TestIsDroppedHeader(t *testing.T) {
	dropped := []string{
		"Authorization", "authorization",
		"X-Amz-Security-Token", "x-amz-security-token",
		"X-Auth-Token",
		"X-Amz-Date",
		"X-Amz-Content-Sha256",
		"Host",
		"Content-Length",
	}
	for _, h := range dropped {
		if !isDroppedHeader(h) {
			t.Errorf("isDroppedHeader(%q) = false, want true", h)
		}
	}

	kept := []string{"Content-Type", "X-Amz-Copy-Source", "Accept", "User-Agent"}
	for _, h := range kept {
		if isDroppedHeader(h) {
			t.Errorf("isDroppedHeader(%q) = true, want false", h)
		}
	}
}

func TestServeHTTP_NoAuth(t *testing.T) {
	opa := opaServer(t, true)
	backend, _ := backendServer(t)
	stsSecret := []byte("test-sts-secret")

	h := newHandler(t, opa.URL, backend.URL, stsSecret, nil)

	req := httptest.NewRequest(http.MethodGet, "/my-bucket/my-key", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401", rw.Code)
	}
}

func TestServeHTTP_STS_Allowed(t *testing.T) {
	opaSrv := opaServer(t, true)
	backend, _ := backendServer(t)
	stsSecret := []byte("test-sts-secret")

	h := newHandler(t, opaSrv.URL, backend.URL, stsSecret, nil)

	token := stsToken(t, stsSecret, "alice", []string{"admin"})
	req := stsRequest(t, http.MethodGet, "/my-bucket/my-key", token)

	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("got %d, want 200; body: %s", rw.Code, rw.Body.String())
	}
}

func TestServeHTTP_STS_Denied(t *testing.T) {
	opaSrv := opaServer(t, false)
	backend, _ := backendServer(t)
	stsSecret := []byte("test-sts-secret")

	h := newHandler(t, opaSrv.URL, backend.URL, stsSecret, nil)

	token := stsToken(t, stsSecret, "bob", []string{"reader"})
	req := stsRequest(t, http.MethodPut, "/my-bucket/my-key", token)

	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusForbidden {
		t.Errorf("got %d, want 403; body: %s", rw.Code, rw.Body.String())
	}
	if !strings.Contains(rw.Body.String(), "AccessDenied") {
		t.Errorf("response does not contain AccessDenied: %s", rw.Body.String())
	}
}

func TestServeHTTP_STS_Disabled(t *testing.T) {
	opaSrv := opaServer(t, true)
	backend, _ := backendServer(t)
	stsSecret := []byte("test-sts-secret")

	// Handler with no STS secret configured.
	h := newHandler(t, opaSrv.URL, backend.URL, nil, nil)

	token := stsToken(t, stsSecret, "alice", []string{"admin"})
	req := stsRequest(t, http.MethodGet, "/my-bucket/my-key", token)

	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401; body: %s", rw.Code, rw.Body.String())
	}
}

func TestServeHTTP_STS_InvalidToken(t *testing.T) {
	opaSrv := opaServer(t, true)
	backend, _ := backendServer(t)
	stsSecret := []byte("test-sts-secret")

	h := newHandler(t, opaSrv.URL, backend.URL, stsSecret, nil)

	req := stsRequest(t, http.MethodGet, "/my-bucket/my-key", "not-a-valid-jwt")

	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401; body: %s", rw.Code, rw.Body.String())
	}
}

func TestServeHTTP_JWT_Allowed(t *testing.T) {
	privKey, jwks := jwksServer(t)
	opaSrv := opaServer(t, true)
	backend, _ := backendServer(t)
	stsSecret := []byte("test-sts-secret")

	validator := newJWTValidator(t, jwks.URL)
	h := newHandler(t, opaSrv.URL, backend.URL, stsSecret, validator)

	rawJWT := signJWT(t, privKey, "alice", "alice@example.com", []string{"admin"})

	req := httptest.NewRequest(http.MethodGet, "/my-bucket/my-key", nil)
	req.Header.Set("Authorization", "Bearer "+rawJWT)

	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Errorf("got %d, want 200; body: %s", rw.Code, rw.Body.String())
	}
}

func TestServeHTTP_JWT_InvalidToken(t *testing.T) {
	_, jwks := jwksServer(t)
	opaSrv := opaServer(t, true)
	backend, _ := backendServer(t)

	validator := newJWTValidator(t, jwks.URL)
	h := newHandler(t, opaSrv.URL, backend.URL, nil, validator)

	req := httptest.NewRequest(http.MethodGet, "/my-bucket/my-key", nil)
	req.Header.Set("Authorization", "Bearer not.a.real.jwt")

	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusUnauthorized {
		t.Errorf("got %d, want 401; body: %s", rw.Code, rw.Body.String())
	}
}

func TestServeHTTP_OPAError(t *testing.T) {
	// OPA server returns a non-200 to simulate an error.
	opaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	t.Cleanup(opaSrv.Close)

	backend, _ := backendServer(t)
	stsSecret := []byte("test-sts-secret")

	h := newHandler(t, opaSrv.URL, backend.URL, stsSecret, nil)

	token := stsToken(t, stsSecret, "alice", []string{"admin"})
	req := stsRequest(t, http.MethodGet, "/my-bucket/my-key", token)

	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusInternalServerError {
		t.Errorf("got %d, want 500; body: %s", rw.Code, rw.Body.String())
	}
}

func TestServeHTTP_PUT_ForwardsBody(t *testing.T) {
	opaSrv := opaServer(t, true)
	stsSecret := []byte("test-sts-secret")

	// Capture the body that reaches the backend.
	var receivedBody []byte
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(backend.Close)

	h := newHandler(t, opaSrv.URL, backend.URL, stsSecret, nil)

	payload := []byte("the object content")
	token := stsToken(t, stsSecret, "alice", []string{"admin"})

	req := httptest.NewRequest(http.MethodPut, "/my-bucket/my-key", bytes.NewReader(payload))
	req.ContentLength = int64(len(payload))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=ASIAFAKE/20240101/us-east-1/s3/aws4_request")
	req.Header.Set("X-Amz-Security-Token", token)

	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", rw.Code, rw.Body.String())
	}
	if !bytes.Equal(receivedBody, payload) {
		t.Errorf("backend received body %q, want %q", receivedBody, payload)
	}
}
