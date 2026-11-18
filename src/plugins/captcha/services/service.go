// Package services implements the captcha plugin: the request hook that protects the configured endpoints
// and the site-verify calls of the four providers (better-auth's verify-handlers).
package services

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/better-go-auth/goauth/src/common/endpointhooks"
	"github.com/better-go-auth/goauth/src/common/logger"
	"github.com/better-go-auth/goauth/src/plugins"
	"github.com/better-go-auth/goauth/src/plugins/captcha/config"
)

// Headers the client sends (better-auth's captcha client contract).
const (
	// HeaderCaptchaResponse carries the token the captcha widget produced.
	HeaderCaptchaResponse = "x-captcha-response"
)

// Error codes and messages (better-auth's EXTERNAL_ERROR_CODES / INTERNAL_ERROR_CODES).
const (
	CodeVerificationFailed = "VERIFICATION_FAILED"
	CodeMissingResponse    = "MISSING_RESPONSE"
	CodeUnknownError       = "UNKNOWN_ERROR"

	MsgVerificationFailed = "Captcha verification failed"
	MsgMissingResponse    = "Missing CAPTCHA response"
	MsgUnknownError       = "Something went wrong"

	// MsgMissingSecretKey and MsgServiceUnavailable are internal: they are logged, the client gets
	// UNKNOWN_ERROR.
	MsgMissingSecretKey   = "Missing secret key"
	MsgServiceUnavailable = "CAPTCHA service unavailable"
)

// ErrorResponse is better-auth's middlewareResponse: the JSON body {message, code} sent through a plain
// `new Response(JSON.stringify(...), {status})`, i.e. with the text/plain content type.
func ErrorResponse(status int, code, message string) *endpointhooks.Response {
	// the field order matches JSON.stringify({message, code})
	body, _ := json.Marshal(struct {
		Message string `json:"message"`
		Code    string `json:"code"`
	}{message, code})
	return &endpointhooks.Response{
		Status: status,
		Header: http.Header{"Content-Type": {"text/plain;charset=UTF-8"}},
		Body:   body,
	}
}

// Service verifies captcha responses with the configured provider.
type Service struct {
	cfg      config.CaptchaConfig
	basePath string
	clientIP func(*http.Request) string
}

// New builds the service. basePath is the auth BasePath; clientIP resolves the client IP sent to the
// provider ("" = none).
func New(cfg config.CaptchaConfig, basePath string, clientIP func(*http.Request) string) *Service {
	if basePath == "" {
		basePath = "/api/auth"
	}
	return &Service{cfg: cfg.WithDefaults(), basePath: basePath, clientIP: clientIP}
}

// Config returns the effective configuration.
func (s *Service) Config() config.CaptchaConfig { return s.cfg }

// Protects reports whether a request path is protected, with better-auth's matching: the first occurrence of
// BasePath is removed from the URL path, and an endpoint matches when it is a substring of the result
// ("/sign-in/email-otp" is exempt unless it is listed in Endpoints).
func (s *Service) Protects(urlPath string) bool {
	// Step 1: the pathname relative to the base path, normalized like better-auth
	pathname := strings.Replace(urlPath, s.basePath, "", 1)
	if strings.HasSuffix(pathname, "//") {
		pathname = pathname[:len(pathname)-1]
	}
	if strings.HasPrefix(pathname, "//") {
		pathname = pathname[1:]
	}
	if !strings.HasPrefix(pathname, "/") {
		pathname = "/" + pathname
	}
	// Step 2: exempt paths (only when the user did not list them)
	var exempt []string
	for _, p := range []string{"/sign-in/email-otp"} {
		if !contains(s.cfg.Endpoints, p) {
			exempt = append(exempt, p)
		}
	}
	// Step 3: substring match against the endpoints
	for _, e := range s.cfg.Endpoints {
		if !strings.Contains(pathname, e) {
			continue
		}
		excluded := false
		for _, p := range exempt {
			if strings.Contains(pathname, p) {
				excluded = true
				break
			}
		}
		if !excluded {
			return true
		}
	}
	return false
}

// OnRequest is the plugin's request hook (better-auth's captcha onRequest). Protected requests need a valid
// x-captcha-response header: a missing one answers 400 MISSING_RESPONSE, a rejected one 403
// VERIFICATION_FAILED, and any failure (missing secret key, provider unreachable or answering an error)
// 500 UNKNOWN_ERROR. Other requests pass through.
func (s *Service) OnRequest(r *http.Request) (*endpointhooks.Response, error) {
	// Step 1: only the protected endpoints
	if r == nil || r.URL == nil || !s.Protects(r.URL.Path) {
		return nil, nil
	}
	// Step 2: verify; internal failures are logged and answered with UNKNOWN_ERROR
	res, err := s.check(r)
	if err != nil {
		logger.Error(err.Error(), "endpoint", r.URL.String(), "message", err)
		return ErrorResponse(http.StatusInternalServerError, CodeUnknownError, MsgUnknownError), nil
	}
	return res, nil
}

// check is the body of better-auth's try block: secret key, header, then the provider call.
func (s *Service) check(r *http.Request) (*endpointhooks.Response, error) {
	// Step 1: a secret key is required to verify anything
	if s.cfg.SecretKey == "" {
		return nil, errors.New(MsgMissingSecretKey)
	}
	// Step 2: the widget's token
	token := r.Header.Get(HeaderCaptchaResponse)
	var remoteIP string
	if s.clientIP != nil {
		remoteIP = s.clientIP(r)
	}
	if token == "" {
		return ErrorResponse(http.StatusBadRequest, CodeMissingResponse, MsgMissingResponse), nil
	}
	// Step 3: ask the provider
	ok, err := s.Verify(r.Context(), token, remoteIP)
	if err != nil {
		return nil, err
	}
	if !ok {
		return ErrorResponse(http.StatusForbidden, CodeVerificationFailed, MsgVerificationFailed), nil
	}
	return nil, nil
}

// Verify sends captchaResponse to the provider's site-verify endpoint and reports whether it was accepted
// (for reCAPTCHA v3 also: score >= MinScore). An error means the provider could not be asked or answered
// with an error status / no data (better-auth's SERVICE_UNAVAILABLE).
func (s *Service) Verify(ctx context.Context, captchaResponse, remoteIP string) (bool, error) {
	// Step 1: the provider's request body
	var (
		body        []byte
		contentType string
	)
	switch s.cfg.Provider {
	case config.CloudflareTurnstile:
		// Turnstile takes JSON
		payload := map[string]string{"secret": s.cfg.SecretKey, "response": captchaResponse}
		if remoteIP != "" {
			payload["remoteip"] = remoteIP
		}
		body, _ = json.Marshal(payload)
		contentType = "application/json"
	case config.GoogleRecaptcha:
		body = formBody([][2]string{{"secret", s.cfg.SecretKey}, {"response", captchaResponse}, {"remoteip", remoteIP}})
		contentType = "application/x-www-form-urlencoded"
	case config.HCaptcha:
		body = formBody([][2]string{{"secret", s.cfg.SecretKey}, {"response", captchaResponse},
			{"sitekey", s.cfg.SiteKey}, {"remoteip", remoteIP}})
		contentType = "application/x-www-form-urlencoded"
	case config.CaptchaFox:
		// CaptchaFox spells the IP field remoteIp
		body = formBody([][2]string{{"secret", s.cfg.SecretKey}, {"response", captchaResponse},
			{"sitekey", s.cfg.SiteKey}, {"remoteIp", remoteIP}})
		contentType = "application/x-www-form-urlencoded"
	default:
		// better-auth's onRequest falls through without a response for an unknown provider
		return true, nil
	}
	// Step 2: POST it
	data, err := s.post(ctx, body, contentType)
	if err != nil {
		return false, err
	}
	// Step 3: success flag, plus the v3 score for reCAPTCHA
	if !plugins.IsTruthy(data["success"]) {
		return false, nil
	}
	if s.cfg.Provider == config.GoogleRecaptcha {
		if score, isV3 := data["score"].(float64); isV3 && score < s.cfg.MinScoreOrDefault() {
			return false, nil
		}
	}
	return true, nil
}

// post sends the verification request and decodes the JSON answer (betterFetch's data). A non-2xx status,
// a transport error or an empty body is SERVICE_UNAVAILABLE; a body that is not a JSON object counts as an
// answer without success.
func (s *Service) post(ctx context.Context, body []byte, contentType string) (map[string]any, error) {
	// Step 1: the request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.cfg.SiteVerifyURL(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", MsgServiceUnavailable, err)
	}
	req.Header.Set("Content-Type", contentType)
	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", MsgServiceUnavailable, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	// Step 2: error statuses and empty answers
	if err != nil || resp.StatusCode < 200 || resp.StatusCode > 299 || len(bytes.TrimSpace(raw)) == 0 {
		return nil, errors.New(MsgServiceUnavailable)
	}
	// Step 3: the JSON answer
	var data map[string]any
	if json.Unmarshal(raw, &data) != nil || data == nil {
		return map[string]any{}, nil
	}
	return data, nil
}

// formBody is better-auth's encodeToURLParams: key=value pairs in order, empty values skipped.
func formBody(pairs [][2]string) []byte {
	parts := make([]string, 0, len(pairs))
	for _, p := range pairs {
		if p[1] == "" {
			continue
		}
		parts = append(parts, url.QueryEscape(p[0])+"="+url.QueryEscape(p[1]))
	}
	return []byte(strings.Join(parts, "&"))
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
