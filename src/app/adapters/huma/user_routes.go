package humaadapter

import (
	"context"
	"net/http"
	"strings"

	authsvc "github.com/better-go-auth/goauth/src/app/services/auth"
	autherr "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/models/dtos"
)

type requestPasswordResetInput struct {
	Body dtos.RequestPasswordResetInput
}

type requestPasswordResetOutput struct {
	Body struct {
		Status  bool   `json:"status"`
		Message string `json:"message"`
	}
}

func (h *handler) requestPasswordReset(ctx context.Context, in *requestPasswordResetInput) (*requestPasswordResetOutput, error) {
	if err := h.checkURL(in.Body.RedirectTo, autherr.ErrInvalidRedirectURL); err != nil {
		return nil, err
	}
	if err := h.Auth.RequestPasswordReset(ctx, in.Body); err != nil {
		return nil, err
	}
	out := &requestPasswordResetOutput{}
	out.Body.Status = true
	out.Body.Message = "If this email exists in our system, check your email for the reset link"
	return out, nil
}

type resetPasswordCallbackInput struct {
	Token       string `path:"token"`
	CallbackURL string `query:"callbackURL"`
}

type redirectOutput struct {
	Status    int
	Location  string        `header:"Location"`
	SetCookie []http.Cookie `header:"Set-Cookie"`
}

// resetPasswordCallback is the link in the reset email: it redirects to callbackURL with ?token= when the
// token is valid, or ?error=INVALID_TOKEN.
func (h *handler) resetPasswordCallback(ctx context.Context, in *resetPasswordCallbackInput) (*redirectOutput, error) {
	if err := h.checkURL(in.CallbackURL, autherr.ErrInvalidCallbackURL); err != nil {
		return nil, err
	}
	out := &redirectOutput{Status: http.StatusFound}
	if in.Token == "" || in.CallbackURL == "" || h.Auth.ValidateResetToken(ctx, in.Token) != nil {
		out.Location = h.errorRedirect(in.CallbackURL, "INVALID_TOKEN")
		return out, nil
	}
	out.Location = h.resolveRedirect(in.CallbackURL, map[string]string{"token": in.Token})
	return out, nil
}

type resetPasswordInput struct {
	Token string `query:"token"`
	Body  struct {
		NewPassword string `json:"newPassword"`
		Token       string `json:"token,omitempty"`
	}
}

func (h *handler) resetPassword(ctx context.Context, in *resetPasswordInput) (*statusOutput, error) {
	tok := in.Body.Token
	if tok == "" {
		tok = in.Token
	}
	if err := h.Auth.ResetPassword(ctx, dtos.ResetPasswordInput{NewPassword: in.Body.NewPassword, Token: tok}); err != nil {
		return nil, err
	}
	return statusOK(), nil
}

type changePasswordInput struct {
	Body dtos.ChangePasswordInput
}

type changePasswordOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Token *string             `json:"token"`
		User  dtos.BetterAuthUser `json:"user"`
	}
}

func (h *handler) changePassword(ctx context.Context, in *changePasswordInput) (*changePasswordOutput, error) {
	res, err := h.Auth.ChangePassword(ctx, current(ctx), in.Body, h.meta(ctx))
	if err != nil {
		return nil, err
	}
	out := &changePasswordOutput{SetCookie: h.sessionCookies(ctx, res.Session)}
	out.Body.Token, out.Body.User = res.Token, res.User
	return out, nil
}

type updateUserInput struct {
	Body map[string]any
}

// updateUser maps the JSON body (camelCase) to the service input; additional fields use their Go field names.
func (h *handler) updateUser(ctx context.Context, in *updateUserInput) (*statusOutput, error) {
	var upd authsvc.UpdateUserInput
	for k, v := range in.Body {
		switch k {
		case "name", "image":
			s, ok := v.(string)
			if !ok && v != nil {
				return nil, autherr.ErrValidationError.WithMessage(k + " must be a string")
			}
			if k == "name" {
				upd.Name = &s
			} else if v != nil {
				upd.Image = &s
			}
		case "email":
			s, _ := v.(string)
			upd.Email = &s
		default:
			if upd.Fields == nil {
				upd.Fields = map[string]any{}
			}
			upd.Fields[strings.ToUpper(k[:1])+k[1:]] = v
		}
	}
	sw, err := h.Auth.UpdateUser(ctx, current(ctx), upd)
	if err != nil {
		return nil, err
	}
	out := statusOK()
	out.SetCookie = h.sessionCookies(ctx, sw)
	return out, nil
}

type deleteUserInput struct {
	Body dtos.DeleteUserInput `required:"false"`
}

type deleteUserOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
}

func (h *handler) deleteUser(ctx context.Context, in *deleteUserInput) (*deleteUserOutput, error) {
	if err := h.checkCallbackURL(in.Body.CallbackURL); err != nil {
		return nil, err
	}
	msg, err := h.Auth.DeleteUser(ctx, current(ctx), in.Body)
	if err != nil {
		return nil, err
	}
	out := &deleteUserOutput{}
	if msg == authsvc.MsgUserDeleted {
		out.SetCookie = h.Cookies.ExpireSessionCookies()
	}
	out.Body.Success, out.Body.Message = true, msg
	return out, nil
}

type deleteUserCallbackInput struct {
	Token       string `query:"token" required:"true"`
	CallbackURL string `query:"callbackURL"`
}

type deleteUserCallbackOutput struct {
	Status    int
	Location  string        `header:"Location"`
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      *struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
}

func (h *handler) deleteUserCallback(ctx context.Context, in *deleteUserCallbackInput) (*deleteUserCallbackOutput, error) {
	if err := h.checkURL(in.CallbackURL, autherr.ErrInvalidCallbackURL); err != nil {
		return nil, err
	}
	if err := h.Auth.DeleteUserCallback(ctx, current(ctx), in.Token); err != nil {
		return nil, err
	}
	out := &deleteUserCallbackOutput{Status: http.StatusOK, SetCookie: h.Cookies.ExpireSessionCookies()}
	if in.CallbackURL != "" {
		out.Status, out.Location = http.StatusFound, in.CallbackURL
		return out, nil
	}
	out.Body = &struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}{Success: true, Message: authsvc.MsgUserDeleted}
	return out, nil
}

type listAccountsOutput struct {
	Body []dtos.AccountResponse
}

func (h *handler) listAccounts(ctx context.Context, _ *struct{}) (*listAccountsOutput, error) {
	accounts, err := h.Auth.ListAccounts(ctx, current(ctx))
	if err != nil {
		return nil, err
	}
	return &listAccountsOutput{Body: accounts}, nil
}

type unlinkAccountInput struct {
	Body dtos.UnlinkAccountInput
}

func (h *handler) unlinkAccount(ctx context.Context, in *unlinkAccountInput) (*statusOutput, error) {
	if err := h.Auth.UnlinkAccount(ctx, current(ctx), in.Body); err != nil {
		return nil, err
	}
	return statusOK(), nil
}
