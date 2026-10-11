package services

import (
	"context"

	"github.com/better-go-auth/goauth/src/app/services/serv_interfaces"
	"github.com/better-go-auth/goauth/src/common/dtos"
	"github.com/better-go-auth/goauth/src/models"
	accesstokendtos "github.com/better-go-auth/goauth/src/plugins/access-token/dtos"
)

// IAccessTokenAuthService defines authentication endpoints for access-token / JWT flow.
type IAccessTokenAuthService interface {
	RegisterWithEmail(ctx context.Context, input models.RegisterClientInput) (dtos.GResp[models.User], error)
	VerifyRegisteredUser(ctx context.Context, input accesstokendtos.VerificationInput) (dtos.GResp[models.User], error)
	Login(ctx context.Context, input accesstokendtos.LoginData) (dtos.GResp[accesstokendtos.TokenResponse], error)
	ResetToken(ctx context.Context, token string) (dtos.GResp[accesstokendtos.TokenResponse], error)
	Logout(ctx context.Context, token string) (dtos.GResp[bool], error)
	ForgotPwd(ctx context.Context, input accesstokendtos.VerifyReqInput) (dtos.GResp[bool], error)
	ResetPwd(ctx context.Context, input accesstokendtos.PwdResetInput) (dtos.GResp[bool], error)
}

// IAccessTokenSessionService manages JWT access token + refresh token sessions.
type IAccessTokenSessionService interface {
	serv_interfaces.LegacySessionService
}

// IAccessTokenProfileService handles user profile operations.
type IAccessTokenProfileService interface {
	GetProfile(ctx context.Context, userID string) (*models.User, error)
	UpdateProfile(ctx context.Context, userID string, update models.ProfileUpdateDto) (*models.User, error)
	ChangePassword(ctx context.Context, userID, sessionID string, update models.PasswordUpdateDto) (dtos.GResp[models.User], error)
	SendChangeEmail(ctx context.Context, userID string, update models.ChangeEmailReqDto) (dtos.GResp[bool], error)
	VerifyChangeEmail(ctx context.Context, userID, sessionID string, update models.VerifyEmailDto) (dtos.GResp[models.User], error)
}
