// Package auth handles OIDC JWT validation using a cached JWKS.
package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

type Claims struct {
	// Subject is the `sub` claim – used as the principal identity sent to OPA.
	Subject string
	// Email is the `email` claim when present.
	Email string
	// Groups is the `groups` claim when present ([]string or []interface{}).
	Groups []string
}

type JWTValidator struct {
	cache    *jwk.Cache
	jwksURL  string
	issuer   string
	audience []string
}

func NewJWTValidator(jwksURL, issuer string, audience []string) (*JWTValidator, error) {
	cache := jwk.NewCache(context.Background())

	if err := cache.Register(jwksURL, jwk.WithMinRefreshInterval(15*time.Minute)); err != nil {
		return nil, fmt.Errorf("register JWKS endpoint %s: %w", jwksURL, err)
	}

	if _, err := cache.Refresh(context.Background(), jwksURL); err != nil {
		return nil, fmt.Errorf("initial JWKS fetch from %s: %w", jwksURL, err)
	}

	return &JWTValidator{
		cache:    cache,
		jwksURL:  jwksURL,
		issuer:   issuer,
		audience: audience,
	}, nil
}

func (v *JWTValidator) Validate(ctx context.Context, rawToken string) (*Claims, error) {
	keyset, err := v.cache.Get(ctx, v.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("retrieve JWKS: %w", err)
	}

	opts := []jwt.ParseOption{
		jwt.WithKeySet(keyset),
		jwt.WithValidate(true),
	}
	if v.issuer != "" {
		opts = append(opts, jwt.WithIssuer(v.issuer))
	}
	for _, aud := range v.audience {
		opts = append(opts, jwt.WithAudience(aud))
	}

	token, err := jwt.ParseString(rawToken, opts...)
	if err != nil {
		return nil, fmt.Errorf("parse/validate JWT: %w", err)
	}

	claims := &Claims{
		Subject: token.Subject(),
		Groups:  ExtractGroups(token),
	}
	if v, ok := token.Get("email"); ok {
		claims.Email, _ = v.(string)
	}

	return claims, nil
}

func (v *JWTValidator) Check(ctx context.Context) error {
	keyset, err := v.cache.Get(ctx, v.jwksURL)
	if err != nil {
		return fmt.Errorf("JWKS cache unavailable: %w", err)
	}
	if keyset.Len() == 0 {
		return fmt.Errorf("JWKS key set is empty")
	}
	return nil
}

func ExtractGroups(token jwt.Token) []string {
	v, ok := token.Get("groups")
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
