package opa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Input is the structured payload sent to OPA for every S3 request.
// The OPA policy receives this as the `input` document.
//
// Example OPA rule:
//
//	package s3
//
//	default allow = false
//
//	allow {
//	    input.action == "GetObject"
//	    input.bucket == "public-data"
//	}
//
//	allow {
//	    input.groups[_] == "data-engineers"
//	}
type Input struct {
	Principal string   `json:"principal"` // JWT `sub` claim
	Email     string   `json:"email,omitempty"`
	Groups    []string `json:"groups"`
	Action    string   `json:"action"` // e.g. "GetObject", "PutObject"
	Bucket    string   `json:"bucket"`
	Key       string   `json:"key,omitempty"` // empty for bucket-level operations
}

type opaRequest struct {
	Input Input `json:"input"`
}

type opaResponse struct {
	Result bool `json:"result"`
}

type Client struct {
	endpoint  string
	healthURL string // derived from endpoint: scheme://host/health
	http      *http.Client
}

func NewClient(endpoint string) *Client {
	healthURL := ""
	if u, err := url.Parse(endpoint); err == nil {
		healthURL = u.Scheme + "://" + u.Host + "/health"
	}
	return &Client{
		endpoint:  endpoint,
		healthURL: healthURL,
		http: &http.Client{
			Timeout: 5 * time.Second,
		},
	}
}

func (c *Client) Check(ctx context.Context) error {
	if c.healthURL == "" {
		return fmt.Errorf("could not derive OPA health URL from endpoint %q", c.endpoint)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.healthURL, nil)
	if err != nil {
		return fmt.Errorf("build OPA health request: %w", err)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("OPA health check: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OPA health returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// Allow posts input to OPA and returns true if the policy evaluates to true.
// A network error or an unexpected OPA status code is returned as an error,
// which the caller should treat as a temporary failure (500), not a deny (403).
func (c *Client) Allow(ctx context.Context, input Input) (bool, error) {
	body, err := json.Marshal(opaRequest{Input: input})
	if err != nil {
		return false, fmt.Errorf("marshal OPA input: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return false, fmt.Errorf("build OPA request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return false, fmt.Errorf("call OPA: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("OPA returned HTTP %d", resp.StatusCode)
	}

	var result opaResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("decode OPA response: %w", err)
	}

	return result.Result, nil
}
