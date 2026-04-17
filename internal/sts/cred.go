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

type Credentials struct {
	AccessKeyID     string
	SecretAccessKey string
	// SessionToken is a signed JWT containing the principal's identity claims.
	// It is passed as X-Amz-Security-Token on every S3 request and validated
	// by the proxy without any persistent state.
	SessionToken string
	Expiration   time.Time
}

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
		Groups:  auth.ExtractGroups(tok),
	}
	if v, ok := tok.Get("email"); ok {
		claims.Email, _ = v.(string)
	}
	return claims, nil
}

func randomAccessKeyID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "SENTINEL" + strings.ToUpper(hex.EncodeToString(b)), nil
}

func randomSecretKey() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
