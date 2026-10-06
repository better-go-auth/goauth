package session

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/src/common/dtos"
	"github.com/better-go-auth/goauth/src/common/types"

	"github.com/better-go-auth/goauth/src/models"
	authDtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
)

func (uh *HumaSessionHandler) DelteMySession(ctx context.Context, dto *types.HumaReqId) (*types.HumaRes[dtos.GResp[authDtos.StatusResponse]], error) {
	v, valid := authenticator.SessionFromContext(ctx)
	if !valid {
		return nil, types.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}
	// if uh.Service.SessionRepo == nil {
	// 	return nil, huma.NewError(http.StatusInternalServerError, "Session repository not configured")
	// }

	session, err := uh.Service.SessionRepo.FindSessionByID(ctx, dto.ID)
	if err != nil || session == nil || session.UserID != v.User.ID {
		return nil, types.NewError(http.StatusNotFound, "Session Not Found")
	}

	err = uh.Service.DeleteSession(ctx, session.ID)
	if err != nil {
		return nil, types.NewError(http.StatusInternalServerError, err.Error())
	}
	return types.MakeRes(dtos.SuccessCreated(authDtos.StatusResponse{Status: true}, 1), 200), nil
}

func (uh *HumaSessionHandler) GetMySession(ctx context.Context, q *models.SessionQuery) (*types.HumaRes[dtos.PResp[[]authDtos.SessionData]], error) {
	v, valid := authenticator.SessionFromContext(ctx)
	if !valid {
		return nil, types.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}
	// if uh.Service.SessionRepo == nil {
	// 	return nil, huma.NewError(http.StatusInternalServerError, "Session repository not configured")
	// }

	sessions, total, err := uh.Service.SessionRepo.QuerySessions(ctx, models.SessionFilter{UserId: v.Session.UserID}, q.PaginationInput)
	if err != nil {
		return types.MakeRes(dtos.PResp[[]authDtos.SessionData]{}, http.StatusInternalServerError), err
	}
	data := authDtos.SessionsToData(sessions)
	return types.MakeRes(dtos.PResp[[]authDtos.SessionData]{
		Body:         data,
		Status:       http.StatusOK,
		RowsAffected: int64(len(data)),
		Count:        total,
	}, 200), nil
}
