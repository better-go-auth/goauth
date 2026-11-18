// Package humamagiclink exposes the magic-link endpoints on a Huma API.
package humamagiclink

import (
	"context"
	"net/http"
	"net/url"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	"github.com/better-go-auth/goauth/src/plugins/magic-link/dtos"
	"github.com/better-go-auth/goauth/src/plugins/magic-link/services"
	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// MagicLinkHandler serves POST /sign-in/magic-link and GET /magic-link/verify.
type MagicLinkHandler struct {
	Service *services.MagicLinkService
	Kit     *pluginkit.Kit
}

// NewMagicLinkHandler builds the handler.
func NewMagicLinkHandler(svc *services.MagicLinkService, kit *pluginkit.Kit) *MagicLinkHandler {
	return &MagicLinkHandler{Service: svc, Kit: kit}
}

// SignInInput is the request of POST /sign-in/magic-link.
type SignInInput struct {
	Body dtos.SignInMagicLinkInput
}

// StatusOutput is the { status: true } response.
type StatusOutput struct {
	Body dtos.StatusResponse
}

// SignIn mirrors better-auth's signInMagicLink: it stores a token and sends the link.
func (h *MagicLinkHandler) SignIn(ctx context.Context, in *SignInInput) (*StatusOutput, error) {
	// Step 1: better-auth's global origin check validates the body redirect targets first
	if err := h.Kit.CheckURL(ctx, in.Body.CallbackURL, autherr.ErrInvalidCallbackURL); err != nil {
		return nil, err
	}
	if err := h.Kit.CheckURL(ctx, in.Body.ErrorCallbackURL, autherr.ErrInvalidErrorCallbackURL); err != nil {
		return nil, err
	}
	if err := h.Kit.CheckURL(ctx, in.Body.NewUserCallbackURL, autherr.ErrInvalidNewUserCallbackURL); err != nil {
		return nil, err
	}
	// Step 2: create the token and send the link
	if err := h.Service.SendMagicLink(ctx, &in.Body, h.Kit.Request(ctx)); err != nil {
		return nil, err
	}
	return &StatusOutput{Body: dtos.StatusResponse{Status: true}}, nil
}

// VerifyInput is the query of GET /magic-link/verify.
type VerifyInput struct {
	Token              string `query:"token" required:"true" doc:"Verification token"`
	CallbackURL        string `query:"callbackURL" doc:"URL to redirect after magic link verification"`
	ErrorCallbackURL   string `query:"errorCallbackURL" doc:"URL to redirect after error"`
	NewUserCallbackURL string `query:"newUserCallbackURL" doc:"URL to redirect after new user signup"`
}

// VerifyOutput is either a JSON body or a 302 redirect, with the session cookies on success.
type VerifyOutput struct {
	Status    int
	Location  string        `header:"Location"`
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      any
}

// Verify mirrors better-auth's magicLinkVerify.
func (h *MagicLinkHandler) Verify(ctx context.Context, in *VerifyInput) (*VerifyOutput, error) {
	// Step 1: decode the redirect targets (better-auth runs decodeURIComponent on the query values)
	rawCallback := decodeURIComponent(in.CallbackURL)
	rawError := decodeURIComponent(in.ErrorCallbackURL)
	rawNewUser := decodeURIComponent(in.NewUserCallbackURL)

	// Step 2: better-auth's originCheck middlewares; all three use the "callbackURL" label, so every
	// untrusted target is reported as INVALID_CALLBACK_URL
	for _, target := range []string{rawCallback, rawNewUser, rawError} {
		if err := h.Kit.CheckURL(ctx, orRoot(target), autherr.ErrInvalidCallbackURL); err != nil {
			return nil, err
		}
	}

	// Step 3: resolve the targets against the base URL (errorCallbackURL/newUserCallbackURL default to callbackURL)
	callbackURL := h.resolve(ctx, orRoot(rawCallback))
	errorCallbackURL := callbackURL
	if rawError != "" {
		errorCallbackURL = h.resolve(ctx, rawError)
	}
	newUserCallbackURL := callbackURL
	if rawNewUser != "" {
		newUserCallbackURL = h.resolve(ctx, rawNewUser)
	}

	// Step 4: consume the token, sign up if needed and create the session
	res, err := h.Service.Verify(ctx, in.Token)
	if err != nil {
		if re := services.AsRedirectError(err); re != nil {
			return &VerifyOutput{
				Status:   http.StatusFound,
				Location: pluginkit.WithQuery(errorCallbackURL, map[string]string{"error": re.Code}),
			}, nil
		}
		return nil, err
	}

	// Step 5: set the session cookies
	out := &VerifyOutput{Status: http.StatusOK, SetCookie: h.Kit.SessionCookies(res.Session, false)}

	// Step 6: without a callbackURL answer with JSON, otherwise redirect (new users go to newUserCallbackURL)
	if in.CallbackURL == "" {
		out.Body = dtos.VerifyMagicLinkResponse{
			Token:   res.Session.Session.Token,
			User:    res.Session.User,
			Session: res.Session.Session,
		}
		return out, nil
	}
	out.Status = http.StatusFound
	if res.IsNewUser {
		out.Location = newUserCallbackURL
	} else {
		out.Location = callbackURL
	}
	return out, nil
}

// resolve is new URL(raw, ctx.context.baseURL).toString(): relative targets are resolved against the base URL
// and an empty path becomes "/".
func (h *MagicLinkHandler) resolve(ctx context.Context, raw string) string {
	resolved := h.Kit.ResolveURL(ctx, raw)
	u, err := url.Parse(resolved)
	if err != nil {
		return resolved
	}
	if u.Host != "" && u.Path == "" && (u.Scheme == "http" || u.Scheme == "https") {
		u.Path = "/"
	}
	return u.String()
}

// orRoot returns "/" for an empty target, like better-auth's `ctx.query.callbackURL ? ... : "/"`.
func orRoot(raw string) string {
	if raw == "" {
		return "/"
	}
	return raw
}

// decodeURIComponent mirrors JavaScript's decodeURIComponent ('+' is kept), returning raw when malformed.
func decodeURIComponent(raw string) string {
	if raw == "" {
		return ""
	}
	if decoded, err := url.PathUnescape(raw); err == nil {
		return decoded
	}
	return raw
}
