package sts

import (
	"strings"
	"testing"
	"time"

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
	if err != nil {
		t.Fatalf("IssueCredentials error: %v", err)
	}

	if !strings.HasPrefix(creds.AccessKeyID, "ASIA") {
		t.Errorf("AccessKeyID %q does not start with ASIA", creds.AccessKeyID)
	}
	if len(creds.AccessKeyID) != 20 {
		t.Errorf("AccessKeyID length = %d, want 20", len(creds.AccessKeyID))
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
	c1, _ := IssueCredentials(testSecret, testClaims(), time.Hour)
	c2, _ := IssueCredentials(testSecret, testClaims(), time.Hour)

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
	if err != nil {
		t.Fatalf("IssueCredentials: %v", err)
	}

	got, err := ValidateSessionToken(testSecret, creds.SessionToken)
	if err != nil {
		t.Fatalf("ValidateSessionToken: %v", err)
	}

	if got.Subject != want.Subject {
		t.Errorf("Subject: got %q, want %q", got.Subject, want.Subject)
	}
	if got.Email != want.Email {
		t.Errorf("Email: got %q, want %q", got.Email, want.Email)
	}
	if len(got.Groups) != len(want.Groups) {
		t.Fatalf("Groups length: got %d, want %d", len(got.Groups), len(want.Groups))
	}
	for i, g := range want.Groups {
		if got.Groups[i] != g {
			t.Errorf("Groups[%d]: got %q, want %q", i, got.Groups[i], g)
		}
	}
}

func TestValidateSessionToken_WrongSecret(t *testing.T) {
	creds, _ := IssueCredentials(testSecret, testClaims(), time.Hour)

	_, err := ValidateSessionToken([]byte("different-secret"), creds.SessionToken)
	if err == nil {
		t.Error("expected error for wrong secret, got nil")
	}
}

func TestValidateSessionToken_Expired(t *testing.T) {
	creds, err := IssueCredentials(testSecret, testClaims(), -time.Second)
	if err != nil {
		t.Fatalf("IssueCredentials: %v", err)
	}

	_, err = ValidateSessionToken(testSecret, creds.SessionToken)
	if err == nil {
		t.Error("expected error for expired token, got nil")
	}
}

func TestValidateSessionToken_Tampered(t *testing.T) {
	creds, _ := IssueCredentials(testSecret, testClaims(), time.Hour)

	parts := strings.Split(creds.SessionToken, ".")
	if len(parts) != 3 {
		t.Fatalf("session token does not have 3 JWT segments")
	}
	parts[1] = "dGFtcGVyZWQ" // base64url("tampered")
	tampered := strings.Join(parts, ".")

	_, err := ValidateSessionToken(testSecret, tampered)
	if err == nil {
		t.Error("expected error for tampered token, got nil")
	}
}

func TestValidateSessionToken_Malformed(t *testing.T) {
	_, err := ValidateSessionToken(testSecret, "not.a.jwt.at.all")
	if err == nil {
		t.Error("expected error for malformed token, got nil")
	}
}
