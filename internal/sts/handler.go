package sts

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/dataminded/s3sentinel/internal/auth"
)

type Config struct {
	JWTValidator *auth.JWTValidator
	TokenSecret  []byte
	TokenTTL     time.Duration
	Logger       *slog.Logger
}

type tokenValidator interface {
	Validate(ctx context.Context, rawToken string) (*auth.Claims, error)
}

type Handler struct {
	jwtValidator tokenValidator
	secret       []byte
	ttl          time.Duration
	logger       *slog.Logger
}

func NewHandler(cfg Config) *Handler {
	return &Handler{
		jwtValidator: cfg.JWTValidator,
		secret:       cfg.TokenSecret,
		ttl:          cfg.TokenTTL,
		logger:       cfg.Logger,
	}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeSTSError(w, http.StatusMethodNotAllowed, "InvalidAction", "only POST is supported")
		return
	}

	if err := r.ParseForm(); err != nil {
		writeSTSError(w, http.StatusBadRequest, "InvalidRequest", "failed to parse request body")
		return
	}

	action := r.FormValue("Action")

	switch action {
	case "AssumeRoleWithWebIdentity":

		response, errorResp := h.assumeRoleWithWebIdentity(r)
		if errorResp != nil {
			writeSTSError(w, errorResp.statusCode, errorResp.code, errorResp.message)
			return
		}
		h.writeResponse(w, response)
	default:
		writeSTSError(w, http.StatusBadRequest, "InvalidAction",
			fmt.Sprintf("action %q is not supported; use AssumeRoleWithWebIdentity", action))
	}
}

func (h *Handler) writeResponse(w http.ResponseWriter, response *assumeRoleWithWebIdentityResponse) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(http.StatusOK)
	_, err := fmt.Fprint(w, xml.Header)
	if err != nil {
		h.logger.Warn("sts: failed to write xml header", "error", err)
	}
	encoder := xml.NewEncoder(w)
	defer func() { _ = encoder.Close() }()
	err = encoder.Encode(response)
	if err != nil {
		h.logger.Error("sts: failed to encode response", "error", err)
	}
}

func (h *Handler) assumeRoleWithWebIdentity(r *http.Request) (*assumeRoleWithWebIdentityResponse, *errorResponse) {
	webIdentityToken := r.FormValue("WebIdentityToken")
	if webIdentityToken == "" {
		return nil, &errorResponse{statusCode: http.StatusBadRequest, code: "MissingParameter", message: "missing web identity token"}
	}

	claims, err := h.jwtValidator.Validate(r.Context(), webIdentityToken)
	if err != nil {
		h.logger.Warn("sts: JWT validation failed", "error", err, "remote", r.RemoteAddr)
		return nil, &errorResponse{statusCode: http.StatusForbidden, code: "InvalidIdentityToken", message: "invalid identity token"}
	}

	creds, err := IssueCredentials(h.secret, claims, h.ttl)
	if err != nil {
		h.logger.Error("sts: failed to issue credentials", "error", err)
		return nil, &errorResponse{statusCode: http.StatusInternalServerError, code: "InvalidIdentityToken", message: "failed to issue credentials"}
	}

	h.logger.Info("sts: issued credentials",
		"principal", claims.Subject,
		"expiration", creds.Expiration,
	)

	roleArn := "arn:aws:sts::000000000000:assumed-role/s3sentinel/" + claims.Subject
	assumedRoleID := "3SENTINEL:" + claims.Subject

	resp := assumeRoleWithWebIdentityResponse{
		Xmlns: "https://sts.amazonaws.com/doc/2011-06-15/",
		Result: assumeRoleResult{
			Credentials: xmlCredentials{
				AccessKeyID:     creds.AccessKeyID,
				SecretAccessKey: creds.SecretAccessKey,
				SessionToken:    creds.SessionToken,
				Expiration:      creds.Expiration.UTC().Format(time.RFC3339),
			},
			AssumedRoleUser: xmlAssumedRoleUser{
				AssumedRoleID: assumedRoleID,
				Arn:           roleArn,
			},
			SubjectFromWebIdentityToken: claims.Subject,
		},
		ResponseMetadata: xmlResponseMetadata{
			RequestID: newRequestID(),
		},
	}
	return &resp, nil
}

type errorResponse struct {
	statusCode int
	code       string
	message    string
}
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
	AccessKeyID     string `xml:"AccessKeyId"`
	SecretAccessKey string `xml:"SecretAccessKey"`
	SessionToken    string `xml:"SessionToken"`
	Expiration      string `xml:"Expiration"`
}

type xmlAssumedRoleUser struct {
	AssumedRoleID string `xml:"AssumedRoleId"`
	Arn           string `xml:"Arn"`
}

type xmlResponseMetadata struct {
	RequestID string `xml:"RequestId"`
}

func writeSTSError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "text/xml")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w,
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
	rand.Read(b) //nolint:errcheck,gosec
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]),
		hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]),
		hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]),
	)
}
