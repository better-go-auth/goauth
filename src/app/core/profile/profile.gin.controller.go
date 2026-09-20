package profile

import (
	"context"
	"net/http"

	"github.com/birukbelay/gocmn/src/dtos"
	"github.com/danielgtaylor/huma/v2"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
)

func (uh *HProfileHandler) GetMyProfile(ctx context.Context, _ *dtos.AuthParam) (*dtos.HumaResponse[dtos.GResp[models.User]], error) {
	v, valid := authenticator.SessionFromContext(ctx)
	if !valid {
		return nil, huma.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}

	user, err := uh.Service.GetProfile(ctx, v.User.ID)
	if err != nil || user == nil {
		return nil, huma.NewError(http.StatusNotFound, "user not found")
	}
	return dtos.HumaReturnG(dtos.SuccessCreated(*user, 1), nil)
}

func (uh *HProfileHandler) UpdateMyProfile(ctx context.Context, filter *dtos.HumaReqBody[models.ProfileUpdateDto]) (*dtos.HumaResponse[dtos.GResp[models.User]], error) {
	v, valid := authenticator.SessionFromContext(ctx)
	if !valid {
		return nil, huma.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}
	user, err := uh.Service.UpdateProfile(ctx, v.User.ID, filter.Body)
	if err != nil || user == nil {
		return nil, huma.NewError(http.StatusInternalServerError, "failed to update profile")
	}
	return dtos.HumaReturnG(dtos.SuccessCreated(*user, 1), nil)
}

func (uh *HProfileHandler) UpdateMyPassword(ctx context.Context, input *dtos.HumaReqBody[models.PasswordUpdateDto]) (*dtos.HumaResponse[dtos.GResp[models.User]], error) {
	v, valid := authenticator.SessionFromContext(ctx)
	if !valid {
		return nil, huma.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}
	resp, err := uh.Service.ChangePassword(ctx, v.User.ID, v.Session.ID, input.Body)
	return dtos.HumaReturnG(resp, err)
}

func (uh *HProfileHandler) UpdateMyEmailReq(ctx context.Context, input *dtos.HumaReqBody[models.ChangeEmailReqDto]) (*dtos.HumaResponse[dtos.GResp[bool]], error) {
	v, valid := authenticator.SessionFromContext(ctx)
	if !valid {
		return nil, huma.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}
	resp, err := uh.Service.SendChangeEmail(ctx, v.User.ID, input.Body)
	return dtos.HumaReturnG(resp, err)
}

func (uh *HProfileHandler) VerifyMyChangeEmailReq(ctx context.Context, input *dtos.HumaReqBody[models.VerifyEmailDto]) (*dtos.HumaResponse[dtos.GResp[bool]], error) {
	v, valid := authenticator.SessionFromContext(ctx)
	if !valid {
		return nil, huma.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}
	resp, err := uh.Service.VerifyChangeEmail(ctx, v.User.ID, input.Body)
	return dtos.HumaReturnG(resp, err)
}

// func (uh *HProfileHandler) DeleteMyProfile(ctx context.Context, _ *dtos.AuthParam) (*dtos.HumaResponse[dtos.GResp[models.User]], error) {
// v, valid := authenticator.SessionFromContext(ctx)
// 	if !valid {
// 		return nil, huma.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
// 	}
// 	resp, err := sql_db.DbUpdateOneById[models.User](uh.CmnServ.GormConn, ctx, v.User.ID, models.UserDto{Active: false, AccountStatus: enums.AccountDeleted}, nil)
// 	return dtos.HumaReturn[models.User](resp, err)
// }
