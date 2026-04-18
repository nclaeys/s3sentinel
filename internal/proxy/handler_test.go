package proxy

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dataminded/s3sentinel/internal/auth"
	"github.com/dataminded/s3sentinel/internal/observability"
	"github.com/dataminded/s3sentinel/internal/opa"
	"github.com/dataminded/s3sentinel/internal/sts"
)

// ── OPA stub ──────────────────────────────────────────────────────────────────

type stubOPA struct {
	allow         bool
	err           error
	capturedInput opa.Input
}

func (s *stubOPA) Check(_ context.Context) error { return nil }

func (s *stubOPA) Allow(_ context.Context, input opa.Input) (bool, error) {
	s.capturedInput = input
	return s.allow, s.err
}

// ── Helpers ───────────────────────────────────────────────────────────────────

var testStsSecret = []byte("test-sts-handler-secret")

func newTestMetrics() *observability.Metrics {
	return observability.NewMetrics(prometheus.NewRegistry())
}

func newTestHandler(opaClient opa.OPAClient, backendURL string) *Handler {
	return NewHandler(Config{
		BackendEndpoint: backendURL,
		BackendRegion:   "us-east-1",
		BackendKey:      "AKIAIOSFODNN7EXAMPLE",
		BackendSecret:   "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		STSTokenSecret:  testStsSecret,
		OPAClient:       opaClient,
		Metrics:         newTestMetrics(),
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
}

func issueToken(t *testing.T, claims *auth.Claims) string {
	t.Helper()
	creds, err := sts.IssueCredentials(testStsSecret, claims, time.Hour)
	require.NoError(t, err)
	return creds.SessionToken
}

// stsRequest builds a request authenticated via AWS4-HMAC-SHA256 + X-Amz-Security-Token,
// which is the STS flow that bypasses the JWTValidator (a concrete struct, not an interface).
func stsRequest(t *testing.T, method, rawURL, sessionToken string) *http.Request {
	t.Helper()
	r := httptest.NewRequestWithContext(t.Context(), method, rawURL, http.NoBody)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=SENTINEL12345678901234/20260417/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=fakesig")
	r.Header.Set("X-Amz-Security-Token", sessionToken)
	return r
}

func testClaims() *auth.Claims {
	return &auth.Claims{
		Subject: "alice",
		Email:   "alice@example.com",
		Groups:  []string{"engineers"},
	}
}

func TestExtractAuth(t *testing.T) {
	tests := []struct {
		name          string
		authorization string
		xAuthToken    string
		xAmzSecurity  string
		wantRaw       string
		wantSession   string
		errExpected   bool
	}{
		{
			name:          "Bearer token",
			authorization: "Bearer my.jwt.token",
			wantRaw:       "my.jwt.token",
		},
		{
			name:       "X-Auth-Token",
			xAuthToken: "my.jwt.token",
			wantRaw:    "my.jwt.token",
		},
		{
			name:          "Bearer takes precedence over X-Auth-Token",
			authorization: "Bearer bearer.token",
			xAuthToken:    "xauth.token",
			wantRaw:       "bearer.token",
		},
		{
			name:          "AWS4 with X-Amz-Security-Token",
			authorization: "AWS4-HMAC-SHA256 Credential=SENTINEL123",
			xAmzSecurity:  "sts.session.token",
			wantSession:   "sts.session.token",
		},
		{
			name:          "AWS4 without X-Amz-Security-Token returns error",
			authorization: "AWS4-HMAC-SHA256 Credential=SENTINEL123",
			errExpected:   true,
		},
		{
			name:        "no credentials returns error",
			errExpected: true,
		},
		{
			name:          "unrecognised Authorization scheme returns error",
			authorization: "Basic dXNlcjpwYXNz",
			errExpected:   true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			if tc.authorization != "" {
				r.Header.Set("Authorization", tc.authorization)
			}
			if tc.xAuthToken != "" {
				r.Header.Set("X-Auth-Token", tc.xAuthToken)
			}
			if tc.xAmzSecurity != "" {
				r.Header.Set("X-Amz-Security-Token", tc.xAmzSecurity)
			}

			raw, session, err := extractAuth(r)
			if tc.errExpected {
				assert.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantRaw, raw)
			assert.Equal(t, tc.wantSession, session)
		})
	}
}

func TestIsDroppedHeader(t *testing.T) {
	alwaysDropped := []string{
		"Authorization",
		"X-Amz-Security-Token",
		"X-Auth-Token",
		"X-Amz-Date",
		"X-Amz-Content-Sha256",
		"Host",
		"Content-Length",
	}
	for _, h := range alwaysDropped {
		t.Run("drop/"+h, func(t *testing.T) {
			assert.True(t, isDroppedHeader(h))
		})
		// Lowercase variants must also be dropped (canonical form matching).
		t.Run("drop/lowercase/"+h, func(t *testing.T) {
			assert.True(t, isDroppedHeader(strings.ToLower(h)))
		})
	}

	alwaysKept := []string{
		"Content-Type",
		"Accept",
		"X-Amz-Copy-Source",
		"X-Custom-Header",
	}
	for _, h := range alwaysKept {
		t.Run("keep/"+h, func(t *testing.T) {
			assert.False(t, isDroppedHeader(h))
		})
	}
}

func TestResolvePayloadHash(t *testing.T) {
	hashOf := func(data []byte) string {
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:])
	}

	t.Run("presigned URL returns UNSIGNED-PAYLOAD", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/bucket/key?X-Amz-Signature=abc", http.NoBody)
		hash, _, _, err := resolvePayloadHash(r)
		require.NoError(t, err)
		assert.Equal(t, "UNSIGNED-PAYLOAD", hash)
	})

	t.Run("UNSIGNED-PAYLOAD header returns UNSIGNED-PAYLOAD", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("data"))
		r.Header.Set("X-Amz-Content-Sha256", "UNSIGNED-PAYLOAD")
		hash, _, _, err := resolvePayloadHash(r)
		require.NoError(t, err)
		assert.Equal(t, "UNSIGNED-PAYLOAD", hash)
	})

	t.Run("STREAMING-AWS4-HMAC-SHA256-PAYLOAD returns UNSIGNED-PAYLOAD", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("data"))
		r.Header.Set("X-Amz-Content-Sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
		hash, _, _, err := resolvePayloadHash(r)
		require.NoError(t, err)
		assert.Equal(t, "UNSIGNED-PAYLOAD", hash)
	})

	t.Run("STREAMING-UNSIGNED-PAYLOAD-TRAILER returns UNSIGNED-PAYLOAD", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPut, "/bucket/key", strings.NewReader("data"))
		r.Header.Set("X-Amz-Content-Sha256", "STREAMING-UNSIGNED-PAYLOAD-TRAILER")
		hash, _, _, err := resolvePayloadHash(r)
		require.NoError(t, err)
		assert.Equal(t, "UNSIGNED-PAYLOAD", hash)
	})

	t.Run("nil body returns empty-body hash", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodGet, "/bucket/key", http.NoBody)
		hash, body, contentLength, err := resolvePayloadHash(r)
		require.NoError(t, err)
		assert.Equal(t, emptyBodyHash, hash)
		assert.Nil(t, body)
		assert.Equal(t, int64(0), contentLength)
	})

	t.Run("body is hashed and buffered", func(t *testing.T) {
		data := []byte("hello world")
		r := httptest.NewRequest(http.MethodPut, "/bucket/key", bytes.NewReader(data))
		r.ContentLength = int64(len(data))

		hash, body, contentLength, err := resolvePayloadHash(r)
		require.NoError(t, err)
		assert.Equal(t, hashOf(data), hash)
		assert.Equal(t, int64(len(data)), contentLength)

		got, err := io.ReadAll(body)
		require.NoError(t, err)
		assert.Equal(t, data, got)
	})
}

func S3BackendReturningError(t *testing.T, errorMsg string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error(errorMsg)
	}))
}

func TestServeHTTP_MissingCredentials(t *testing.T) {
	backend := S3BackendReturningError(t, "backend must not be reached when auth is missing")
	defer backend.Close()

	h := newTestHandler(&stubOPA{allow: true}, backend.URL)
	r := httptest.NewRequest(http.MethodGet, "/mybucket/mykey", http.NoBody)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidToken")
}

func TestServeHTTP_STS_NotConfigured(t *testing.T) {
	backend := S3BackendReturningError(t, "backend must not be reached when STS is not configured")
	defer backend.Close()

	h := NewHandler(Config{
		STSTokenSecret:  nil, // STS not configured
		BackendEndpoint: backend.URL,
		BackendRegion:   "us-east-1",
		BackendKey:      "key",
		BackendSecret:   "secret",
		OPAClient:       &stubOPA{allow: true},
		Metrics:         newTestMetrics(),
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
	})

	r := httptest.NewRequest(http.MethodGet, "/mybucket/mykey", http.NoBody)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=SENTINEL123")
	r.Header.Set("X-Amz-Security-Token", "some.sts.token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestServeHTTP_InvalidSTSToken(t *testing.T) {
	backend := S3BackendReturningError(t, "backend must not be reached when STS token is invalid")
	defer backend.Close()

	h := newTestHandler(&stubOPA{allow: true}, backend.URL)

	r := httptest.NewRequest(http.MethodGet, "/mybucket/mykey", http.NoBody)
	r.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential=SENTINEL123")
	r.Header.Set("X-Amz-Security-Token", "not.a.valid.jwt")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestServeHTTP_OPADeny(t *testing.T) {
	backend := S3BackendReturningError(t, "backend must not be reached when OPA denies")
	defer backend.Close()

	h := newTestHandler(&stubOPA{allow: false}, backend.URL)
	token := issueToken(t, testClaims())

	r := stsRequest(t, http.MethodGet, "/mybucket/mykey", token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "AccessDenied")
}

func TestServeHTTP_OPAError(t *testing.T) {
	backend := S3BackendReturningError(t, "backend must not be reached when OPA is unavailable")
	defer backend.Close()

	h := newTestHandler(&stubOPA{err: errors.New("opa unavailable")}, backend.URL)
	token := issueToken(t, testClaims())

	r := stsRequest(t, http.MethodGet, "/mybucket/mykey", token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "InternalError")
}

func TestServeHTTP_OPAReceivesCorrectInput(t *testing.T) {
	backend := S3BackendSuccessWithBody(t, "", "")
	defer backend.Close()

	stub := &stubOPA{allow: true}
	h := newTestHandler(stub, backend.URL)
	claims := testClaims()
	token := issueToken(t, claims)

	r := stsRequest(t, http.MethodGet, "http://proxy.example.com/mybucket/mykey", token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, claims.Subject, stub.capturedInput.Principal)
	assert.Equal(t, claims.Email, stub.capturedInput.Email)
	assert.Equal(t, claims.Groups, stub.capturedInput.Groups)
	assert.Equal(t, "GetObject", stub.capturedInput.Action)
	assert.Equal(t, "mybucket", stub.capturedInput.Bucket)
	assert.Equal(t, "mykey", stub.capturedInput.Key)
}

func S3BackendSuccessWithBody(t *testing.T, body, backendHeaderKey string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if backendHeaderKey != "" {
			w.Header().Set(backendHeaderKey, backendHeaderKey)
		}
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte(body))
		assert.NoError(t, err)
	}))
}

func TestServeHTTP_ForwardResponseToClient(t *testing.T) {
	backendHeader := "X-Backend-Header"
	backendBody := "object body"
	backend := S3BackendSuccessWithBody(t, backendBody, backendHeader)
	defer backend.Close()

	h := newTestHandler(&stubOPA{allow: true}, backend.URL)
	token := issueToken(t, testClaims())

	r := stsRequest(t, http.MethodGet, "http://proxy.example.com/mybucket/mykey", token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, backendBody, w.Body.String())
	assert.Equal(t, backendHeader, w.Header().Get(backendHeader))
}

func TestServeHTTP_ForwardStripsAuthHeaders(t *testing.T) {
	var captured *http.Request
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	h := newTestHandler(&stubOPA{allow: true}, backend.URL)
	token := issueToken(t, testClaims())

	r := stsRequest(t, http.MethodGet, "http://proxy.example.com/mybucket/mykey", token)
	r.Header.Set("X-Custom-Passthrough", "keep-me")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.NotNil(t, captured)
	assert.Contains(t, captured.Header.Get("Authorization"), "AKIAIOSFODNN7EXAMPLE", "re-signed with backend key")
	assert.NotContains(t, captured.Header.Get("Authorization"), "fakesig", "client signature must not reach backend")
	assert.Empty(t, captured.Header.Get("X-Amz-Security-Token"), "client session token should be stripped")
	assert.Empty(t, captured.Header.Get("X-Auth-Token"), "X-Auth-Token should be stripped")
	assert.Equal(t, "keep-me", captured.Header.Get("X-Custom-Passthrough"))
}

func TestServeHTTP_ForwardQueryString(t *testing.T) {
	var captured *http.Request
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		captured = r
		w.WriteHeader(http.StatusOK)
	}))
	defer backend.Close()

	h := newTestHandler(&stubOPA{allow: true}, backend.URL)
	token := issueToken(t, testClaims())

	r := stsRequest(t, http.MethodGet, "http://proxy.example.com/mybucket?list-type=2&prefix=data/", token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.NotNil(t, captured)
	assert.Equal(t, "2", captured.URL.Query().Get("list-type"))
	assert.Equal(t, "data/", captured.URL.Query().Get("prefix"))
}

func TestServeHTTP_BackendNon200ProxiedToClient(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("<Error><Code>NoSuchKey</Code></Error>"))
	}))
	defer backend.Close()

	h := newTestHandler(&stubOPA{allow: true}, backend.URL)
	token := issueToken(t, testClaims())

	r := stsRequest(t, http.MethodGet, "http://proxy.example.com/mybucket/missing-key", token)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusNotFound, w.Code)
	assert.Contains(t, w.Body.String(), "NoSuchKey")
}
