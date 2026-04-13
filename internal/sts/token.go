// Package sts implements stateless credential vending compatible with the AWS
// AssumeRoleWithWebIdentity API.
//
// The SessionToken issued by this package is a signed JWT (HS256) that encodes
// the principal's identity (sub, email, groups) and an expiry. The proxy
// validates the SessionToken on every request, extracting the identity without
// any shared state or database lookup.
package sts

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"github.com/dataminded/s3sentinel/internal/auth"
)

const sessionTokenIssuer = "s3sentinel-sts"

// Credentials holds the temporary AWS-compatible credentials issued by the STS handler.
type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	// SessionToken is a signed JWT containing the principal's identity claims.
	// It is passed as X-Amz-Security-Token on every S3 request and validated
	// by the proxy without any persistent state.
	SessionToken string
	Expiration   time.Time
}

// IssueCredentials mints a new set of temporary credentials for the given claims.
// secret is the HMAC key used to sign the SessionToken JWT.
func IssueCredentials(secret []byte, claims *auth.Claims, ttl time.Duration) (*Credentials, error) {
	now := time.Now().UTC()
	exp := now.Add(ttl)

	accessKeyID, err := randomAccessKeyID()
	if err != nil {
		return nil, fmt.Errorf("generate access key ID: %w", err)
	}

	secretKey, err := randomSecretKey()
	if err != nil {
		return nil, fmt.Errorf("generate secret key: %w", err)
	}

	tok, err := jwt.NewBuilder().
		Issuer(sessionTokenIssuer).
		Subject(claims.Subject).
		IssuedAt(now).
		Expiration(exp).
		Claim("email", claims.Email).
		Claim("groups", claims.Groups).
		Build()
	if err != nil {
		return nil, fmt.Errorf("build session token: %w", err)
	}

	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.HS256, secret))
	if err != nil {
		return nil, fmt.Errorf("sign session token: %w", err)
	}

	return &Credentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretKey,
		SessionToken:    string(signed),
		Expiration:      exp,
	}, nil
}

// ValidateSessionToken parses and validates a SessionToken JWT issued by IssueCredentials.
// It returns the identity claims encoded in the token.
func ValidateSessionToken(secret []byte, tokenStr string) (*auth.Claims, error) {
	tok, err := jwt.Parse([]byte(tokenStr),
		jwt.WithKey(jwa.HS256, secret),
		jwt.WithValidate(true),
		jwt.WithIssuer(sessionTokenIssuer),
	)
	if err != nil {
		return nil, fmt.Errorf("validate session token: %w", err)
	}

	claims := &auth.Claims{
		Subject: tok.Subject(),
		Groups:  extractGroups(tok),
	}
	if v, ok := tok.Get("email"); ok {
		claims.Email, _ = v.(string)
	}
	return claims, nil
}

// extractGroups reads the "groups" claim, tolerating both []string and
// []interface{} encodings that different JWT libraries produce.
func extractGroups(tok jwt.Token) []string {
	v, ok := tok.Get("groups")
	if !ok {
		return nil
	}
	switch g := v.(type) {
	case []string:
		return g
	case []interface{}:
		out := make([]string, 0, len(g))
		for _, item := range g {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// randomAccessKeyID generates an AWS-style temporary access key: "ASIA" + 16 uppercase hex chars.
func randomAccessKeyID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "ASIA" + strings.ToUpper(hex.EncodeToString(b)), nil
}

// randomSecretKey generates a 40-character hex string for the secret access key.
func randomSecretKey() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
