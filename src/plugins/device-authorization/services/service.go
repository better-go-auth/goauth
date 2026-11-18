// Package services implements better-auth's device-authorization plugin (RFC 8628): device / user code
// issuance, token polling, and the user's verification, approval and denial.
package services

import (
	"context"
	"crypto/rand"
	"errors"
	"math"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/better-go-auth/goauth/src/adapter"
	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	modeldtos "github.com/better-go-auth/goauth/src/models/dtos"
	daconfig "github.com/better-go-auth/goauth/src/plugins/device-authorization/config"
	"github.com/better-go-auth/goauth/src/plugins/device-authorization/dtos"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
	"github.com/better-go-auth/goauth/src/providers/idgen"
)

// Model is the logical name of the plugin's table.
const Model = "deviceCode"

// Logical field names of the deviceCode table.
const (
	FieldDeviceCode      = "deviceCode"
	FieldUserCode        = "userCode"
	FieldUserID          = "userId"
	FieldExpiresAt       = "expiresAt"
	FieldStatus          = "status"
	FieldLastPolledAt    = "lastPolledAt"
	FieldPollingInterval = "pollingInterval"
	FieldClientID        = "clientId"
	FieldScope           = "scope"
)

// Service implements the device authorization flow on top of the plugin's deviceCode table.
type Service struct {
	cfg   daconfig.DeviceAuthorizationConfig
	kit   *pluginkit.Kit
	store adapter.Adapter

	mu  sync.RWMutex
	now func() time.Time
}

// New builds the service. store is the adapter holding the deviceCode table (InitContext.Adapter).
func New(cfg daconfig.DeviceAuthorizationConfig, kit *pluginkit.Kit, store adapter.Adapter) *Service {
	return &Service{cfg: cfg.WithDefaults(), kit: kit, store: store, now: time.Now}
}

// Config returns the effective configuration.
func (s *Service) Config() daconfig.DeviceAuthorizationConfig { return s.cfg }

// Kit returns the shared plugin runtime.
func (s *Service) Kit() *pluginkit.Kit { return s.kit }

// SetClock overrides the clock used for expiry and polling checks (tests). nil restores time.Now.
func (s *Service) SetClock(now func() time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if now == nil {
		now = time.Now
	}
	s.now = now
}

// clock returns the current time.
func (s *Service) clock() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.now()
}

// ─── POST /device/code ───────────────────────────────────────────────────────

// RequestCode is POST /device/code: it validates the client, stores a pending device code and returns the
// RFC 8628 device authorization response.
func (s *Service) RequestCode(ctx context.Context, clientID string, scope *string) (*dtos.DeviceCodeResponse, error) {
	// Step 1: the client must be known (validateClient)
	if s.cfg.ValidateClient != nil {
		ok, err := s.cfg.ValidateClient(ctx, clientID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrInvalidClientID
		}
	}
	// Step 2: the application's hook (onDeviceAuthRequest)
	if s.cfg.OnDeviceAuthRequest != nil {
		if err := s.cfg.OnDeviceAuthRequest(ctx, clientID, scope); err != nil {
			return nil, err
		}
	}
	// Step 3: generate the device code and the user code
	deviceCode, err := s.generateDeviceCode(ctx)
	if err != nil {
		return nil, err
	}
	userCode, err := s.generateUserCode(ctx)
	if err != nil {
		return nil, err
	}
	// Step 4: store the pending authorization (pollingInterval in milliseconds, like better-auth)
	expiresAt := s.clock().Add(s.cfg.ExpiresIn)
	data := adapter.Record{
		FieldDeviceCode:      deviceCode,
		FieldUserCode:        userCode,
		FieldUserID:          nil,
		FieldExpiresAt:       expiresAt,
		FieldStatus:          dtos.StatusPending,
		FieldPollingInterval: float64(s.cfg.Interval.Milliseconds()),
		FieldClientID:        clientID,
	}
	if scope != nil {
		data[FieldScope] = *scope
	}
	if _, err := s.store.Create(ctx, Model, data); err != nil {
		return nil, err
	}
	// Step 5: the verification URIs and the response
	uri, complete := s.VerificationURIs(ctx, userCode)
	return &dtos.DeviceCodeResponse{
		DeviceCode:              deviceCode,
		UserCode:                userCode,
		VerificationURI:         uri,
		VerificationURIComplete: complete,
		ExpiresIn:               int64(s.cfg.ExpiresIn / time.Second),
		Interval:                int64(s.cfg.Interval / time.Second),
	}, nil
}

// VerificationURIs is better-auth's buildVerificationUris: VerificationURI (default "/device") as an
// absolute URL, or resolved against the auth base URL, and the same URL with ?user_code=<userCode>.
func (s *Service) VerificationURIs(ctx context.Context, userCode string) (string, string) {
	// Step 1: absolute URLs are used as is, anything else is resolved against the base URL
	raw := s.cfg.VerificationURI
	if raw == "" {
		raw = daconfig.DefaultVerificationURI
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() || u.Host == "" {
		base, berr := url.Parse(s.kit.RequestBaseURL(ctx))
		if berr != nil {
			return raw, raw
		}
		ref, rerr := url.Parse(raw)
		if rerr != nil {
			return raw, raw
		}
		u = base.ResolveReference(ref)
	}
	// Step 2: WHATWG URLs always have a path ("https://example.com" → "https://example.com/")
	if u.Path == "" && u.Opaque == "" {
		u.Path = "/"
	}
	// Step 3: the complete URI carries the user code (URLSearchParams.set)
	complete := *u
	complete.RawQuery = setQueryParam(u.RawQuery, "user_code", userCode)
	return u.String(), complete.String()
}

// setQueryParam is URLSearchParams.set + toString: the other parameters keep their order, the first key
// parameter is replaced in place (later ones are dropped) or the parameter is appended, and every pair is
// form-encoded.
func setQueryParam(rawQuery, key, value string) string {
	var pairs []string
	set := false
	for part := range strings.SplitSeq(rawQuery, "&") {
		if part == "" {
			continue
		}
		k, v, _ := strings.Cut(part, "=")
		k, _ = url.QueryUnescape(k)
		v, _ = url.QueryUnescape(v)
		if k == key {
			if set {
				continue
			}
			v, set = value, true
		}
		pairs = append(pairs, url.QueryEscape(k)+"="+url.QueryEscape(v))
	}
	if !set {
		pairs = append(pairs, url.QueryEscape(key)+"="+url.QueryEscape(value))
	}
	return strings.Join(pairs, "&")
}

// generateDeviceCode returns GenerateDeviceCode's code or DeviceCodeLength random [a-zA-Z0-9] characters.
func (s *Service) generateDeviceCode(ctx context.Context) (string, error) {
	if s.cfg.GenerateDeviceCode != nil {
		return s.cfg.GenerateDeviceCode(ctx)
	}
	return idgen.RandomString(s.cfg.DeviceCodeLength), nil
}

// generateUserCode returns GenerateUserCode's code or UserCodeLength characters of UserCodeCharset.
func (s *Service) generateUserCode(ctx context.Context) (string, error) {
	if s.cfg.GenerateUserCode != nil {
		return s.cfg.GenerateUserCode(ctx)
	}
	return DefaultUserCode(s.cfg.UserCodeLength)
}

// DefaultUserCode is better-auth's defaultGenerateUserCode: length random bytes mapped onto the 32
// characters of UserCodeCharset (byte % 32, unbiased since 256 is a multiple of 32).
func DefaultUserCode(length int) (string, error) {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, length)
	for i, b := range buf {
		out[i] = daconfig.UserCodeCharset[int(b)%len(daconfig.UserCodeCharset)]
	}
	return string(out), nil
}

// ─── POST /device/token ──────────────────────────────────────────────────────

// Token is POST /device/token (RFC 8628 §3.4/3.5): it answers authorization_pending, slow_down,
// expired_token or access_denied until the user approved, then creates a session for the user and returns
// its token as access_token. The device code is single use.
func (s *Service) Token(ctx context.Context, deviceCode, clientID string) (*dtos.DeviceTokenResponse, error) {
	// Step 1: the client must be known (validateClient)
	if s.cfg.ValidateClient != nil {
		ok, err := s.cfg.ValidateClient(ctx, clientID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, ErrInvalidGrantClientID
		}
	}
	// Step 2: load the device code; it must belong to the polling client
	rec, err := s.find(ctx, FieldDeviceCode, deviceCode)
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, ErrInvalidDeviceCode
	}
	if rec.ClientID != nil && *rec.ClientID != "" && *rec.ClientID != clientID {
		return nil, ErrClientIDMismatch
	}
	// Step 3: enforce the polling interval, then remember this poll
	now := s.clock()
	if rec.LastPolledAt != nil && rec.PollingInterval != nil && *rec.PollingInterval != 0 {
		if float64(now.Sub(*rec.LastPolledAt).Milliseconds()) < *rec.PollingInterval {
			return nil, ErrPollingTooFrequently
		}
	}
	if _, err := s.store.UpdateMany(ctx, Model, idWhere(rec.ID), adapter.Record{FieldLastPolledAt: now}); err != nil {
		return nil, err
	}
	// Step 4: expired codes are removed
	if rec.ExpiresAt.Before(now) {
		_ = s.store.Delete(ctx, Model, idWhere(rec.ID))
		return nil, ErrExpiredDeviceCode
	}
	// Step 5: answer according to the user's decision
	switch {
	case rec.Status == dtos.StatusPending:
		return nil, ErrAuthorizationPending
	case rec.Status == dtos.StatusDenied:
		_ = s.store.Delete(ctx, Model, idWhere(rec.ID))
		return nil, ErrAccessDeniedPoll
	case rec.Status == dtos.StatusApproved && rec.UserID != nil && *rec.UserID != "":
		return s.issue(ctx, rec, now)
	}
	return nil, ErrInvalidStatus
}

// issue consumes an approved device code and creates the user's session.
func (s *Service) issue(ctx context.Context, rec *dtos.DeviceCode, now time.Time) (*dtos.DeviceTokenResponse, error) {
	// Step 1: the approving user must still exist
	user, err := pluginkit.AcceptNotFound(s.kit.Repos.FindUserByID(ctx, *rec.UserID))
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}
	// Step 2: consume the code first, so two concurrent polls cannot both get a session
	n, err := s.store.DeleteMany(ctx, Model, []adapter.Where{
		{Field: "id", Value: rec.ID}, {Field: FieldStatus, Value: dtos.StatusApproved},
	})
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, ErrInvalidDeviceCode
	}
	// Step 3: create the session (session hooks such as the admin ban check may veto it)
	sw, err := s.kit.CreateSession(ctx, user, false)
	if err != nil {
		if errors.Is(err, autherr.ErrFailedToCreateSession) {
			return nil, ErrFailedToCreateSess
		}
		return nil, err
	}
	// Step 4: the token response
	scope := ""
	if rec.Scope != nil {
		scope = *rec.Scope
	}
	expires := time.Time(sw.Session.ExpiresAt)
	return &dtos.DeviceTokenResponse{
		AccessToken: sw.Session.Token,
		TokenType:   "Bearer",
		ExpiresIn:   int64(math.Floor(expires.Sub(now).Seconds())),
		Scope:       scope,
	}, nil
}

// ─── GET /device, POST /device/approve, POST /device/deny ────────────────────

// Verify is GET /device: it checks the user code and, when the request has a session and nobody claimed
// the code yet, claims it for the signed-in user (approve and deny require that claim).
func (s *Service) Verify(ctx context.Context, userCode string, current *modeldtos.SessionWithUser) (*dtos.DeviceVerifyResponse, error) {
	// Step 1: find the code (dashes are ignored) and check its expiry
	rec, err := s.findUserCode(ctx, userCode)
	if err != nil {
		return nil, err
	}
	// Step 2: claim it for the signed-in user (compare-and-swap on pending + unclaimed)
	if current != nil && current.User.ID != "" && rec.UserID == nil && rec.Status == dtos.StatusPending {
		if _, err := s.store.UpdateMany(ctx, Model, []adapter.Where{
			{Field: "id", Value: rec.ID},
			{Field: FieldStatus, Value: dtos.StatusPending},
			{Field: FieldUserID, Value: nil},
		}, adapter.Record{FieldUserID: current.User.ID}); err != nil {
			return nil, err
		}
	}
	return &dtos.DeviceVerifyResponse{UserCode: userCode, Status: rec.Status}, nil
}

// Approve is POST /device/approve: the user who claimed the code approves it.
func (s *Service) Approve(ctx context.Context, userCode string, current *modeldtos.SessionWithUser) error {
	return s.decide(ctx, userCode, current, dtos.StatusApproved, ErrNotYourApproval)
}

// Deny is POST /device/deny: the user who claimed the code denies it.
func (s *Service) Deny(ctx context.Context, userCode string, current *modeldtos.SessionWithUser) error {
	return s.decide(ctx, userCode, current, dtos.StatusDenied, ErrNotYourDenial)
}

// decide records the user's decision on a claimed, pending code.
func (s *Service) decide(ctx context.Context, userCode string, current *modeldtos.SessionWithUser, status string, notYours error) error {
	// Step 1: a session is required
	if current == nil || current.User.ID == "" {
		return ErrAuthenticationNeeded
	}
	// Step 2: the code must exist, be live, pending, and claimed by this user
	rec, err := s.findUserCode(ctx, userCode)
	if err != nil {
		return err
	}
	if rec.Status != dtos.StatusPending {
		return ErrAlreadyProcessed
	}
	if rec.UserID == nil || *rec.UserID == "" {
		return ErrNotClaimed
	}
	if *rec.UserID != current.User.ID {
		return notYours
	}
	// Step 3: store the decision while the code is still pending
	n, err := s.store.UpdateMany(ctx, Model, []adapter.Where{
		{Field: "id", Value: rec.ID}, {Field: FieldStatus, Value: dtos.StatusPending},
	}, adapter.Record{FieldStatus: status, FieldUserID: current.User.ID})
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrAlreadyProcessed
	}
	return nil
}

// findUserCode loads a live code by user code (dashes removed): INVALID_USER_CODE when unknown,
// EXPIRED_USER_CODE when expired.
func (s *Service) findUserCode(ctx context.Context, userCode string) (*dtos.DeviceCode, error) {
	rec, err := s.find(ctx, FieldUserCode, strings.ReplaceAll(userCode, "-", ""))
	if err != nil {
		return nil, err
	}
	if rec == nil {
		return nil, ErrInvalidUserCode
	}
	if rec.ExpiresAt.Before(s.clock()) {
		return nil, ErrExpiredUserCode
	}
	return rec, nil
}

// ─── storage ─────────────────────────────────────────────────────────────────

// FindByUserCode returns the device code with userCode (dashes ignored), or nil. Applications building
// their own verification page can use it to show the client and scope.
func (s *Service) FindByUserCode(ctx context.Context, userCode string) (*dtos.DeviceCode, error) {
	return s.find(ctx, FieldUserCode, strings.ReplaceAll(userCode, "-", ""))
}

// find loads the first device code whose field equals value (nil when there is none).
func (s *Service) find(ctx context.Context, field, value string) (*dtos.DeviceCode, error) {
	rec, err := s.store.FindOne(ctx, Model, []adapter.Where{{Field: field, Value: value}})
	if errors.Is(err, adapter.ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return fromRecord(rec), nil
}

// fromRecord converts an adapter record to a DeviceCode.
func fromRecord(rec adapter.Record) *dtos.DeviceCode {
	out := &dtos.DeviceCode{
		ID:         str(rec["id"]),
		DeviceCode: str(rec[FieldDeviceCode]),
		UserCode:   str(rec[FieldUserCode]),
		Status:     str(rec[FieldStatus]),
		UserID:     strPtr(rec[FieldUserID]),
		ClientID:   strPtr(rec[FieldClientID]),
		Scope:      strPtr(rec[FieldScope]),
	}
	if t, ok := rec[FieldExpiresAt].(time.Time); ok {
		out.ExpiresAt = t
	}
	if t, ok := rec[FieldLastPolledAt].(time.Time); ok {
		out.LastPolledAt = &t
	}
	switch v := rec[FieldPollingInterval].(type) {
	case float64:
		out.PollingInterval = &v
	case int64:
		f := float64(v)
		out.PollingInterval = &f
	}
	return out
}

// idWhere matches one record by id.
func idWhere(id string) []adapter.Where { return []adapter.Where{{Field: "id", Value: id}} }

// str returns v as a string ("" for nil).
func str(v any) string {
	s, _ := v.(string)
	return s
}

// strPtr returns v as a *string (nil for nil).
func strPtr(v any) *string {
	s, ok := v.(string)
	if !ok {
		return nil
	}
	return &s
}
