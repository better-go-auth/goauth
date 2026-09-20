package session

import (
	"context"
	"net/http"

	"github.com/birukbelay/gocmn/src/dtos"
	"github.com/danielgtaylor/huma/v2"

	"github.com/better-go-auth/goauth/src/models"
	authDtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
)

func (uh *HumaSessionHandler) DelteMySession(ctx context.Context, dto *dtos.HumaInputId) (*dtos.HumaResponse[dtos.GResp[authDtos.StatusResponse]], error) {
	v, valid := authenticator.SessionFromContext(ctx)
	if !valid {
		return nil, huma.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}
	// if uh.Service.SessionRepo == nil {
	// 	return nil, huma.NewError(http.StatusInternalServerError, "Session repository not configured")
	// }

	session, err := uh.Service.SessionRepo.GetSessionBySessionID(ctx, dto.ID)
	if err != nil || session == nil {
		session, err = uh.Service.SessionRepo.GetSessionByID(ctx, dto.ID)
	}
	if err != nil || session == nil || session.UserID != v.User.ID {
		return nil, huma.NewError(http.StatusNotFound, "Session Not Found")
	}

	err = uh.Service.DeleteSession(ctx, session.SessionId)
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, err.Error())
	}
	return dtos.HumaReturnG(dtos.SuccessCreated(authDtos.StatusResponse{Status: true}, 1), nil)
}

func (uh *HumaSessionHandler) GetMySession(ctx context.Context, q *models.SessionQuery) (*dtos.HumaResponse[dtos.PResp[[]authDtos.SessionData]], error) {
	v, valid := authenticator.SessionFromContext(ctx)
	if !valid {
		return nil, huma.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}
	// if uh.Service.SessionRepo == nil {
	// 	return nil, huma.NewError(http.StatusInternalServerError, "Session repository not configured")
	// }

	sessions, total, err := uh.Service.SessionRepo.ListSessions(ctx, models.SessionFilter{UserId: v.Session.UserID}, q.PaginationInput)
	if err != nil {
		return dtos.PHumaReturn(dtos.PResp[[]authDtos.SessionData]{}, err)
	}
	data := authDtos.SessionsToData(sessions)
	return dtos.PHumaReturn(dtos.PResp[[]authDtos.SessionData]{
		Body:         data,
		Status:       http.StatusOK,
		RowsAffected: int64(len(data)),
		Count:        total,
	}, nil)
}
