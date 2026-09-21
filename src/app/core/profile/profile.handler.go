package profile

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/src/common/dtos"
	humatypes "github.com/better-go-auth/goauth/src/common/types"
	"github.com/danielgtaylor/huma/v2"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
)

func (uh *HProfileHandler) GetMyProfile(ctx context.Context, _ *humatypes.HumaReqEmpty) (*humatypes.HumaRes[dtos.GResp[models.User]], error) {
	v, valid := authenticator.SessionFromContext(ctx)
	if !valid {
		return nil, huma.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}

	user, err := uh.Service.GetProfile(ctx, v.User.ID)
	if err != nil || user == nil {
		return nil, huma.NewError(http.StatusNotFound, "user not found")
	}
	return humatypes.MakeRes(dtos.SuccessCreated(*user, 1), 200), nil
}

func (uh *HProfileHandler) UpdateMyProfile(ctx context.Context, filter *humatypes.HumaReqBody[models.ProfileUpdateDto]) (*humatypes.HumaRes[dtos.GResp[models.User]], error) {
	v, valid := authenticator.SessionFromContext(ctx)
	if !valid {
		return nil, huma.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}
	user, err := uh.Service.UpdateProfile(ctx, v.User.ID, filter.Body)
	if err != nil || user == nil {
		return nil, huma.NewError(http.StatusInternalServerError, "failed to update profile")
	}
	return humatypes.MakeRes(dtos.SuccessCreated(*user, 1), 201), nil
}

func (uh *HProfileHandler) UpdateMyPassword(ctx context.Context, input *humatypes.HumaReqBody[models.PasswordUpdateDto]) (*humatypes.HumaRes[dtos.GResp[models.User]], error) {
	v, valid := authenticator.SessionFromContext(ctx)
	if !valid {
		return nil, huma.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}
	resp, err := uh.Service.ChangePassword(ctx, v.User.ID, v.Session.ID, input.Body)
	if err != nil {
		// todo make a func that returns huma error with the error message
		return nil, huma.NewError(http.StatusInternalServerError, err.Error())
	}
	return humatypes.MakeRes(resp, 200), nil
}

func (uh *HProfileHandler) UpdateMyEmailReq(ctx context.Context, input *humatypes.HumaReqBody[models.ChangeEmailReqDto]) (*humatypes.HumaRes[dtos.GResp[bool]], error) {
	v, valid := authenticator.SessionFromContext(ctx)
	if !valid {
		return nil, huma.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}
	resp, err := uh.Service.SendChangeEmail(ctx, v.User.ID, input.Body)
	if err != nil {
		// todo make a func that returns huma error with the error message
		return nil, huma.NewError(http.StatusInternalServerError, err.Error())
	}
	return humatypes.MakeRes(resp, 200), nil
}

func (uh *HProfileHandler) VerifyMyChangeEmailReq(ctx context.Context, input *humatypes.HumaReqBody[models.VerifyEmailDto]) (*humatypes.HumaRes[dtos.GResp[bool]], error) {
	v, valid := authenticator.SessionFromContext(ctx)
	if !valid {
		return nil, huma.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}
	resp, err := uh.Service.VerifyChangeEmail(ctx, v.User.ID, input.Body)
	if err != nil {
		// todo make a func that returns huma error with the error message
		return nil, huma.NewError(http.StatusInternalServerError, err.Error())
	}
	return humatypes.MakeRes(resp, 200), nil
}

// func (uh *HProfileHandler) DeleteMyProfile(ctx context.Context, _ *dtos.AuthParam) (*dtos.HumaResponse[dtos.GResp[models.User]], error) {
// v, valid := authenticator.SessionFromContext(ctx)
// 	if !valid {
// 		return nil, huma.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
// 	}
// 	resp, err := sql_db.DbUpdateOneById[models.User](uh.CmnServ.GormConn, ctx, v.User.ID, models.UserDto{Active: false, AccountStatus: enums.AccountDeleted}, nil)
// 	return dtos.HumaReturn[models.User](resp, err)
// }
