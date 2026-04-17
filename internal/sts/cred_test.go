package sts

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/dataminded/s3sentinel/internal/auth"
)

var testSecret = []byte("test-secret-for-unit-tests")

func testClaims() *auth.Claims {
	return &auth.Claims{
		Subject: "alice",
		Email:   "alice@example.com",
		Groups:  []string{"admin", "reader"},
	}
}

func TestIssueCredentials_CredentialFormat(t *testing.T) {
	creds, err := IssueCredentials(testSecret, testClaims(), time.Hour)
	assert.NoError(t, err)

	if !strings.HasPrefix(creds.AccessKeyID, "SENTINEL") {
		t.Errorf("AccessKeyID %q does not start with SENTINEL", creds.AccessKeyID)
	}
	if len(creds.AccessKeyID) != 24 {
		t.Errorf("AccessKeyID length = %d, want 24", len(creds.AccessKeyID))
	}

	if len(creds.SecretAccessKey) != 40 {
		t.Errorf("SecretAccessKey length = %d, want 40", len(creds.SecretAccessKey))
	}

	if creds.SessionToken == "" {
		t.Error("SessionToken is empty")
	}

	if !creds.Expiration.After(time.Now()) {
		t.Errorf("Expiration %v is not in the future", creds.Expiration)
	}
}

func TestIssueCredentials_UniquePerCall(t *testing.T) {
	c1, err := IssueCredentials(testSecret, testClaims(), time.Hour)
	assert.NoError(t, err)
	c2, err2 := IssueCredentials(testSecret, testClaims(), time.Hour)
	assert.NoError(t, err2)

	if c1.AccessKeyID == c2.AccessKeyID {
		t.Error("expected unique AccessKeyIDs across calls")
	}
	if c1.SecretAccessKey == c2.SecretAccessKey {
		t.Error("expected unique SecretAccessKeys across calls")
	}
}

func TestValidateSessionToken_RoundTrip(t *testing.T) {
	want := testClaims()

	creds, err := IssueCredentials(testSecret, want, time.Hour)
	assert.NoError(t, err)
	got, err := ValidateSessionToken(testSecret, creds.SessionToken)
	assert.NoError(t, err)

	assert.Equal(t, want, got)
}

func TestValidateSessionToken_WrongSecret(t *testing.T) {
	creds, _ := IssueCredentials(testSecret, testClaims(), time.Hour)

	_, err := ValidateSessionToken([]byte("different-secret"), creds.SessionToken)

	assert.Error(t, err)
}

func TestValidateSessionToken_Expired(t *testing.T) {
	creds, err := IssueCredentials(testSecret, testClaims(), -time.Second)
	if err != nil {
		t.Fatalf("IssueCredentials: %v", err)
	}

	_, err = ValidateSessionToken(testSecret, creds.SessionToken)

	assert.Error(t, err)
}

func TestValidateSessionToken_Tampered(t *testing.T) {
	creds, _ := IssueCredentials(testSecret, testClaims(), time.Hour)

	parts := strings.Split(creds.SessionToken, ".")
	assert.Len(t, parts, 3, "session token should have 3 JWT segments")
	parts[1] = "dGFtcGVyZWQ" // base64url("tampered")
	tampered := strings.Join(parts, ".")
	_, err := ValidateSessionToken(testSecret, tampered)

	assert.Error(t, err)
}

func TestValidateSessionToken_Malformed(t *testing.T) {
	_, err := ValidateSessionToken(testSecret, "not.a.jwt.at.all")

	assert.Error(t, err)
}
