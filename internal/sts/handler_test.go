package sts

import (
	"context"
	"encoding/xml"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/dataminded/s3sentinel/internal/auth"
)

type stubValidator struct {
	claims *auth.Claims
	err    error
}

func (s *stubValidator) Validate(_ context.Context, _ string) (*auth.Claims, error) {
	return s.claims, s.err
}

func newHandlerWithValidator(v tokenValidator) *Handler {
	return &Handler{
		jwtValidator: v,
		secret:       testSecret,
		ttl:          time.Hour,
		logger:       slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func stsPostRequest(action, token string) *http.Request {
	form := url.Values{"Action": {action}}
	if token != "" {
		form.Set("WebIdentityToken", token)
	}
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func TestSTSHandler_NonPost(t *testing.T) {
	h := newHandlerWithValidator(&stubValidator{claims: testClaims()})

	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			r := httptest.NewRequest(method, "/", nil)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
			assert.Contains(t, w.Body.String(), "InvalidAction")
		})
	}
}

func TestSTSHandler_UnsupportedAction(t *testing.T) {
	h := newHandlerWithValidator(&stubValidator{claims: testClaims()})

	r := stsPostRequest("GetCallerIdentity", "some.token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidAction")
}

func TestSTSHandler_MissingWebIdentityToken(t *testing.T) {
	h := newHandlerWithValidator(&stubValidator{claims: testClaims()})

	form := url.Values{"Action": {"AssumeRoleWithWebIdentity"}}
	r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "MissingParameter")
}

func TestSTSHandler_InvalidJWT(t *testing.T) {
	h := newHandlerWithValidator(&stubValidator{err: errors.New("bad token")})

	r := stsPostRequest("AssumeRoleWithWebIdentity", "bad.jwt.token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	assert.Equal(t, http.StatusForbidden, w.Code)
	assert.Contains(t, w.Body.String(), "InvalidIdentityToken")
}

func TestSTSHandler_Success(t *testing.T) {
	claims := testClaims()
	h := newHandlerWithValidator(&stubValidator{claims: claims})

	r := stsPostRequest("AssumeRoleWithWebIdentity", "valid.jwt.token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/xml", w.Header().Get("Content-Type"))

	var resp assumeRoleWithWebIdentityResponse
	require.NoError(t, xml.NewDecoder(strings.NewReader(w.Body.String())).Decode(&resp))

	assert.Equal(t, claims.Subject, resp.Result.SubjectFromWebIdentityToken)
	assert.NotEmpty(t, resp.Result.Credentials.AccessKeyId)
	assert.NotEmpty(t, resp.Result.Credentials.SecretAccessKey)
	assert.NotEmpty(t, resp.Result.Credentials.SessionToken)
	assert.NotEmpty(t, resp.Result.Credentials.Expiration)
	assert.NotEmpty(t, resp.ResponseMetadata.RequestId)
}

func TestSTSHandler_Success_RoleArn(t *testing.T) {
	claims := &auth.Claims{Subject: "bob", Email: "bob@example.com"}
	h := newHandlerWithValidator(&stubValidator{claims: claims})

	r := stsPostRequest("AssumeRoleWithWebIdentity", "valid.jwt.token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)

	var resp assumeRoleWithWebIdentityResponse
	require.NoError(t, xml.NewDecoder(strings.NewReader(w.Body.String())).Decode(&resp))

	assert.Contains(t, resp.Result.AssumedRoleUser.Arn, "bob")
	assert.Contains(t, resp.Result.AssumedRoleUser.AssumedRoleId, "bob")
}

func TestSTSHandler_Success_SessionTokenValidates(t *testing.T) {
	claims := testClaims()
	h := newHandlerWithValidator(&stubValidator{claims: claims})

	r := stsPostRequest("AssumeRoleWithWebIdentity", "valid.jwt.token")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)

	require.Equal(t, http.StatusOK, w.Code)

	var resp assumeRoleWithWebIdentityResponse
	require.NoError(t, xml.NewDecoder(strings.NewReader(w.Body.String())).Decode(&resp))

	got, err := ValidateSessionToken(testSecret, resp.Result.Credentials.SessionToken)
	require.NoError(t, err)
	assert.Equal(t, claims, got)
}
