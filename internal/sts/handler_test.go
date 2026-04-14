package sts

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"encoding/xml"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/dataminded/s3sentinel/internal/auth"
)

const testIssuer = "https://test.example.com"

// jwksServer starts an httptest server that serves a single RSA public key as JWKS
// and returns the private key for signing test JWTs.
func jwksServer(t *testing.T) (*rsa.PrivateKey, *httptest.Server) {
	t.Helper()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}

	pubJWK, err := jwk.FromRaw(privKey.Public())
	if err != nil {
		t.Fatalf("create JWK from public key: %v", err)
	}
	pubJWK.Set(jwk.KeyIDKey, "test-kid")    //nolint:errcheck
	pubJWK.Set(jwk.AlgorithmKey, jwa.RS256) //nolint:errcheck

	set := jwk.NewSet()
	set.AddKey(pubJWK) //nolint:errcheck

	keyJSON, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(keyJSON) //nolint:errcheck
	}))
	t.Cleanup(srv.Close)
	return privKey, srv
}

// signJWT signs a JWT with the given RSA private key, using testIssuer.
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
		t.Fatalf("create private JWK: %v", err)
	}
	privJWK.Set(jwk.KeyIDKey, "test-kid")    //nolint:errcheck
	privJWK.Set(jwk.AlgorithmKey, jwa.RS256) //nolint:errcheck

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.RS256, privJWK))
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return string(signed)
}

// newSTSHandler builds a ready-to-use STS Handler backed by a real JWTValidator
// pointed at the given JWKS server.
func newSTSHandler(t *testing.T, jwksURL string) *Handler {
	t.Helper()

	validator, err := auth.NewJWTValidator(jwksURL, testIssuer, nil)
	if err != nil {
		t.Fatalf("NewJWTValidator: %v", err)
	}

	return NewHandler(Config{
		JWTValidator: validator,
		TokenSecret:  testSecret,
		TokenTTL:     time.Hour,
		Logger:       slog.Default(),
	})
}

func postSTS(t *testing.T, h http.Handler, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	body := strings.NewReader(form.Encode())
	req := httptest.NewRequest(http.MethodPost, "/", body)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)
	return rw
}

func TestSTSHandler_MethodNotAllowed(t *testing.T) {
	privKey, jwks := jwksServer(t)
	_ = privKey
	h := newSTSHandler(t, jwks.URL)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rw := httptest.NewRecorder()
	h.ServeHTTP(rw, req)

	if rw.Code != http.StatusMethodNotAllowed {
		t.Errorf("got %d, want 405", rw.Code)
	}
}

func TestSTSHandler_UnknownAction(t *testing.T) {
	privKey, jwks := jwksServer(t)
	_ = privKey
	h := newSTSHandler(t, jwks.URL)

	rw := postSTS(t, h, url.Values{"Action": {"ListBuckets"}})
	if rw.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", rw.Code)
	}
	if !strings.Contains(rw.Body.String(), "InvalidAction") {
		t.Errorf("response body does not contain InvalidAction: %s", rw.Body.String())
	}
}

func TestSTSHandler_MissingWebIdentityToken(t *testing.T) {
	privKey, jwks := jwksServer(t)
	_ = privKey
	h := newSTSHandler(t, jwks.URL)

	rw := postSTS(t, h, url.Values{"Action": {"AssumeRoleWithWebIdentity"}})
	if rw.Code != http.StatusBadRequest {
		t.Errorf("got %d, want 400", rw.Code)
	}
	if !strings.Contains(rw.Body.String(), "MissingParameter") {
		t.Errorf("response body does not contain MissingParameter: %s", rw.Body.String())
	}
}

func TestSTSHandler_InvalidJWT(t *testing.T) {
	privKey, jwks := jwksServer(t)
	_ = privKey
	h := newSTSHandler(t, jwks.URL)

	rw := postSTS(t, h, url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"WebIdentityToken": {"not.a.valid.jwt"},
	})
	if rw.Code != http.StatusForbidden {
		t.Errorf("got %d, want 403", rw.Code)
	}
	if !strings.Contains(rw.Body.String(), "InvalidIdentityToken") {
		t.Errorf("response body does not contain InvalidIdentityToken: %s", rw.Body.String())
	}
}

func TestSTSHandler_ValidRequest(t *testing.T) {
	privKey, jwks := jwksServer(t)
	h := newSTSHandler(t, jwks.URL)

	rawJWT := signJWT(t, privKey, "alice", "alice@example.com", []string{"admin", "reader"})

	rw := postSTS(t, h, url.Values{
		"Action":           {"AssumeRoleWithWebIdentity"},
		"WebIdentityToken": {rawJWT},
	})

	if rw.Code != http.StatusOK {
		t.Fatalf("got %d, want 200; body: %s", rw.Code, rw.Body.String())
	}

	// Parse the XML response.
	var resp assumeRoleWithWebIdentityResponse
	body := rw.Body.String()
	// Strip the XML declaration line before unmarshalling.
	if idx := strings.Index(body, "<AssumeRoleWithWebIdentityResponse"); idx >= 0 {
		body = body[idx:]
	}
	if err := xml.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("unmarshal XML response: %v\nbody: %s", err, rw.Body.String())
	}

	creds := resp.Result.Credentials

	if !strings.HasPrefix(creds.AccessKeyId, "ASIA") {
		t.Errorf("AccessKeyId %q does not start with ASIA", creds.AccessKeyId)
	}
	if len(creds.AccessKeyId) != 20 {
		t.Errorf("AccessKeyId length = %d, want 20", len(creds.AccessKeyId))
	}
	if len(creds.SecretAccessKey) != 40 {
		t.Errorf("SecretAccessKey length = %d, want 40", len(creds.SecretAccessKey))
	}
	if creds.SessionToken == "" {
		t.Error("SessionToken is empty")
	}

	// The session token must be decodable and contain the original claims.
	claims, err := ValidateSessionToken(testSecret, creds.SessionToken)
	if err != nil {
		t.Fatalf("ValidateSessionToken: %v", err)
	}
	if claims.Subject != "alice" {
		t.Errorf("Subject: got %q, want %q", claims.Subject, "alice")
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("Email: got %q, want %q", claims.Email, "alice@example.com")
	}

	if resp.Result.SubjectFromWebIdentityToken != "alice" {
		t.Errorf("SubjectFromWebIdentityToken: got %q, want alice", resp.Result.SubjectFromWebIdentityToken)
	}
}
