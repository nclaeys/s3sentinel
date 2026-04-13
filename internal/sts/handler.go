package sts

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/dataminded/s3sentinel/internal/auth"
)

// Config holds the STS handler's dependencies.
type Config struct {
	JWTValidator *auth.JWTValidator
	TokenSecret  []byte
	TokenTTL     time.Duration
	Logger       *slog.Logger
}

// Handler implements the STS AssumeRoleWithWebIdentity endpoint.
// It validates an OIDC JWT and issues short-lived AWS-compatible credentials
// whose SessionToken encodes the principal's identity for stateless validation
// by the proxy on every subsequent S3 request.
type Handler struct {
	jwtValidator *auth.JWTValidator
	secret       []byte
	ttl          time.Duration
	logger       *slog.Logger
}

// NewHandler creates a new STS Handler.
func NewHandler(cfg Config) *Handler {
	return &Handler{
		jwtValidator: cfg.JWTValidator,
		secret:       cfg.TokenSecret,
		ttl:          cfg.TokenTTL,
		logger:       cfg.Logger,
	}
}

// ServeHTTP handles STS requests. Only POST requests are accepted.
// The Action is read from the query string or the form body.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeSTSError(w, http.StatusMethodNotAllowed, "InvalidAction", "only POST is supported")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeSTSError(w, http.StatusBadRequest, "InvalidRequest", "failed to parse request body")
		return
	}

	// Action may appear in the query string or the form body.
	action := r.FormValue("Action")

	switch action {
	case "AssumeRoleWithWebIdentity":
		h.assumeRoleWithWebIdentity(w, r)
	default:
		writeSTSError(w, http.StatusBadRequest, "InvalidAction",
			fmt.Sprintf("action %q is not supported; use AssumeRoleWithWebIdentity", action))
	}
}

func (h *Handler) assumeRoleWithWebIdentity(w http.ResponseWriter, r *http.Request) {
	webIdentityToken := r.FormValue("WebIdentityToken")
	if webIdentityToken == "" {
		writeSTSError(w, http.StatusBadRequest, "MissingParameter", "WebIdentityToken is required")
		return
	}

	claims, err := h.jwtValidator.Validate(r.Context(), webIdentityToken)
	if err != nil {
		h.logger.Warn("sts: JWT validation failed", "error", err, "remote", r.RemoteAddr)
		writeSTSError(w, http.StatusForbidden, "InvalidIdentityToken", "JWT validation failed: "+err.Error())
		return
	}

	creds, err := IssueCredentials(h.secret, claims, h.ttl)
	if err != nil {
		h.logger.Error("sts: failed to issue credentials", "error", err)
		writeSTSError(w, http.StatusInternalServerError, "ServiceUnavailable", "credential issuance failed")
		return
	}

	h.logger.Info("sts: issued credentials",
		"principal", claims.Subject,
		"expiration", creds.Expiration,
	)

	roleArn := "arn:aws:sts::000000000000:assumed-role/s3sentinel/" + claims.Subject
	assumedRoleID := "AROAS3SENTINEL:" + claims.Subject

	resp := assumeRoleWithWebIdentityResponse{
		Xmlns: "https://sts.amazonaws.com/doc/2011-06-15/",
		Result: assumeRoleResult{
			Credentials: xmlCredentials{
				AccessKeyId:     creds.AccessKeyID,
				SecretAccessKey: creds.SecretAccessKey,
				SessionToken:    creds.SessionToken,
				Expiration:      creds.Expiration.UTC().Format(time.RFC3339),
			},
			AssumedRoleUser: xmlAssumedRoleUser{
				AssumedRoleId: assumedRoleID,
				Arn:           roleArn,
			},
			SubjectFromWebIdentityToken: claims.Subject,
		},
		ResponseMetadata: xmlResponseMetadata{
			RequestId: newRequestID(),
		},
	}

	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, xml.Header)
	if err := xml.NewEncoder(w).Encode(resp); err != nil {
		h.logger.Error("sts: failed to encode response", "error", err)
	}
}

// --- XML response types -------------------------------------------------------

type assumeRoleWithWebIdentityResponse struct {
	XMLName          xml.Name            `xml:"AssumeRoleWithWebIdentityResponse"`
	Xmlns            string              `xml:"xmlns,attr"`
	Result           assumeRoleResult    `xml:"AssumeRoleWithWebIdentityResult"`
	ResponseMetadata xmlResponseMetadata `xml:"ResponseMetadata"`
}

type assumeRoleResult struct {
	Credentials                 xmlCredentials     `xml:"Credentials"`
	AssumedRoleUser             xmlAssumedRoleUser `xml:"AssumedRoleUser"`
	SubjectFromWebIdentityToken string             `xml:"SubjectFromWebIdentityToken"`
}

type xmlCredentials struct {
	AccessKeyId     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

type xmlAssumedRoleUser struct {
	AssumedRoleId string `xml:"AssumedRoleId"`
	Arn           string `xml:"Arn"`
}

type xmlResponseMetadata struct {
	RequestId string `xml:"RequestId"`
}

func writeSTSError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	fmt.Fprintf(w,
		`<?xml version="1.0" encoding="UTF-8"?>`+"\n"+
			`<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">`+"\n"+
			`  <Error><Type>Sender</Type><Code>%s</Code><Message>%s</Message></Error>`+"\n"+
			`  <RequestId>%s</RequestId>`+"\n"+
			`</ErrorResponse>`,
		code, message, newRequestID(),
	)
}

func newRequestID() string {
	b := make([]byte, 16)
	rand.Read(b) //nolint:errcheck — rand.Read never errors on modern Go
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	)
}
