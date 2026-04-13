package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config holds all runtime configuration for the proxy.
type Config struct {
	// Network
	ListenAddr string // default: :8080
	AdminAddr  string // default: :9090 — serves /healthz, /readyz, /metrics

	// Back-end EU cloud S3 (OVH, Scaleway, Exoscale, Hetzner, …)
	BackendEndpoint string // e.g. https://s3.gra.io.cloud.ovh.net
	BackendRegion   string // e.g. gra, nl-ams-1, ch-gva-2
	BackendKey      string // service-account access key (full bucket access)
	BackendSecret   string // service-account secret key

	// ProxyHost is the domain the proxy itself is reachable on.
	// When set, virtual-hosted-style requests (<bucket>.<ProxyHost>/key) are
	// detected and the bucket is extracted from the Host header.
	// Example: "s3.internal.example.com"
	ProxyHost string

	// TLS — both fields must be set to enable HTTPS.
	// The proxy serves plain HTTP when either field is empty.
	TLSCertFile string // path to PEM-encoded certificate (or full chain)
	TLSKeyFile  string // path to PEM-encoded private key

	// OPA
	// Full URL to the OPA policy rule endpoint, e.g.:
	//   http://opa:8181/v1/data/s3/allow
	OPAEndpoint string

	// OIDC / JWT
	JWKSEndpoint string   // JWKS URI of your IdP
	JWTIssuer    string   // expected `iss` claim (recommended)
	JWTAudience  []string // expected `aud` claim(s), comma-separated in env

	// STS — credential vending (optional).
	// When STSTokenSecret is empty the STS server is not started and the proxy
	// only accepts Bearer / X-Auth-Token JWT authentication.
	STSListenAddr  string        // default: :8090
	STSTokenSecret []byte        // HMAC key for signing/validating SessionToken JWTs
	STSTokenTTL    time.Duration // lifetime of issued credentials (default: 1h)
}

// Load reads configuration from environment variables and returns an error
// if any required variable is absent.
func Load() (Config, error) {
	stsSecret := []byte(os.Getenv("STS_TOKEN_SECRET"))
	if len(stsSecret) == 0 {
		stsSecret = nil
	}
	stsTTL, err := parseDuration(os.Getenv("STS_TOKEN_TTL"), time.Hour)
	if err != nil {
		return Config{}, fmt.Errorf("STS_TOKEN_TTL: %w", err)
	}

	cfg := Config{
		ListenAddr:      getenv("LISTEN_ADDR", ":8080"),
		AdminAddr:       getenv("ADMIN_ADDR", ":9090"),
		BackendEndpoint: os.Getenv("BACKEND_ENDPOINT"),
		BackendRegion:   getenv("BACKEND_REGION", "us-east-1"),
		BackendKey:      os.Getenv("BACKEND_ACCESS_KEY"),
		BackendSecret:   os.Getenv("BACKEND_SECRET_KEY"),
		ProxyHost:       os.Getenv("PROXY_HOST"),
		TLSCertFile:     os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:      os.Getenv("TLS_KEY_FILE"),
		OPAEndpoint:     os.Getenv("OPA_ENDPOINT"),
		JWKSEndpoint:    os.Getenv("JWKS_ENDPOINT"),
		JWTIssuer:       os.Getenv("JWT_ISSUER"),
		JWTAudience:     splitCSV(os.Getenv("JWT_AUDIENCE")),
		STSListenAddr:   getenv("STS_LISTEN_ADDR", ":8090"),
		STSTokenSecret:  stsSecret,
		STSTokenTTL:     stsTTL,
	}

	required := map[string]string{
		"BACKEND_ENDPOINT":   cfg.BackendEndpoint,
		"BACKEND_ACCESS_KEY": cfg.BackendKey,
		"BACKEND_SECRET_KEY": cfg.BackendSecret,
		"OPA_ENDPOINT":       cfg.OPAEndpoint,
		"JWKS_ENDPOINT":      cfg.JWKSEndpoint,
	}
	var missing []string
	for k, v := range required {
		if v == "" {
			missing = append(missing, k)
		}
	}
	if len(missing) > 0 {
		return Config{}, errors.New("missing required environment variables: " + strings.Join(missing, ", "))
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return Config{}, errors.New("TLS_CERT_FILE and TLS_KEY_FILE must both be set to enable TLS")
	}
	return cfg, nil
}

// TLSEnabled reports whether TLS should be used for the listening socket.
func (c Config) TLSEnabled() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// STSEnabled reports whether the STS credential-vending server should be started.
func (c Config) STSEnabled() bool {
	return len(c.STSTokenSecret) > 0
}

func getenv(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

// parseDuration parses s as a time.Duration, returning defaultVal when s is empty.
func parseDuration(s string, defaultVal time.Duration) (time.Duration, error) {
	if s == "" {
		return defaultVal, nil
	}
	return time.ParseDuration(s)
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}
