package humaaccesstoken

import (
	"context"
	"net/http"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	"github.com/better-go-auth/goauth/src/common/dtos"
	"github.com/better-go-auth/goauth/src/common/types"
	"github.com/better-go-auth/goauth/src/models"
	authDtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/providers/authenticator"
)

// DeleteMySession handles POST /session/{id}.
func (h *AccessTokenHandler) DeleteMySession(ctx context.Context, dto *types.HumaReqId) (*types.HumaRes[dtos.GResp[authDtos.StatusResponse]], error) {
	v, valid := authenticator.SessionFromContext(ctx)
	if !valid {
		return nil, types.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}
	// if uh.Service.SessionRepo == nil {
	// 	return nil, huma.NewError(http.StatusInternalServerError, "Session repository not configured")
	// }

	if h.SessionRepo != nil {
		session, err := h.SessionRepo.FindSessionByID(ctx, dto.ID)
		if err != nil || session == nil || session.UserID != v.User.ID {
			return nil, types.NewError(http.StatusNotFound, "Session Not Found")
		}
	}

	err := h.SessionServ.DeleteSession(ctx, dto.ID)
	if err != nil {
		return nil, types.NewError(http.StatusInternalServerError, err.Error())
	}
	return types.MakeRes(dtos.SuccessCreated(authDtos.StatusResponse{Status: true}, 1), 200), nil
}

// DelteMySession is an alias for DeleteMySession.
func (h *AccessTokenHandler) DelteMySession(ctx context.Context, dto *types.HumaReqId) (*types.HumaRes[dtos.GResp[authDtos.StatusResponse]], error) {
	return h.DeleteMySession(ctx, dto)
}

// GetMySession handles GET /session.
func (h *AccessTokenHandler) GetMySession(ctx context.Context, q *models.SessionQuery) (*types.HumaRes[dtos.PResp[[]authDtos.SessionData]], error) {
	v, valid := authenticator.SessionFromContext(ctx)
	if !valid {
		return nil, types.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}
	// if uh.Service.SessionRepo == nil {
	// 	return nil, huma.NewError(http.StatusInternalServerError, "Session repository not configured")
	// }

	if h.SessionRepo != nil {
		sessions, total, err := h.SessionRepo.QuerySessions(ctx, models.SessionFilter{UserId: v.Session.UserID}, q.PaginationInput)
		if err != nil {
			return types.MakeRes(dtos.PResp[[]authDtos.SessionData]{}, http.StatusInternalServerError), err
		}
		return types.MakeRes(dtos.PResp[[]authDtos.SessionData]{
			Body:         authDtos.SessionsToData(sessions),
			Status:       http.StatusOK,
			RowsAffected: int64(len(sessions)),
			Count:        total,
		}, 200), nil
	}

	return types.MakeRes(dtos.PResp[[]authDtos.SessionData]{
		Body:         []authDtos.SessionData{v.Session},
		Status:       http.StatusOK,
		RowsAffected: 1,
		Count:        1,
	}, 200), nil
}

// Ensure SessionRepo is declared on AccessTokenHandler
type sessionRepoCarrier interface {
	repo_interfaces.ISessionRepo
}
