package session

import (
	"context"
	"net/http"

	"github.com/birukbelay/gocmn/src/consts"
	"github.com/birukbelay/gocmn/src/crypto"
	"github.com/birukbelay/gocmn/src/dtos"
	"github.com/birukbelay/gocmn/src/generic"
	"github.com/danielgtaylor/huma/v2"

	"github.com/better-go-auth/goauth/src/models"
	authDtos "github.com/better-go-auth/goauth/src/models/dtos"
)

func (uh *HumaSessionHandler) DelteMySession(ctx context.Context, dto *dtos.HumaInputId) (*dtos.HumaResponse[dtos.GResp[authDtos.StatusResponse]], error) {
	v, ok := ctx.Value(consts.CtxClaims.Str()).(crypto.CustomClaims)
	if !ok {
		return nil, huma.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}
	session, err := generic.DbGetOne[models.Session](uh.Service.ProvServ.GormConn, ctx, models.SessionFilter{UserId: v.UserId, SessionId: dto.ID}, nil)
	if err != nil {
		return nil, huma.NewError(http.StatusNotFound, "Session NOt Found")
	}
	err = uh.Service.DeleteSession(ctx, session.Body.SessionId)
	if err != nil {
		return nil, huma.NewError(http.StatusInternalServerError, err.Error())
	}
	return dtos.HumaReturnG(dtos.SuccessS(authDtos.StatusResponse{Status: true}, 1), nil)
}

func (uh *HumaSessionHandler) GetMySession(ctx context.Context, q *models.SessionQuery) (*dtos.HumaResponse[dtos.PResp[[]authDtos.SessionData]], error) {
	v, ok := ctx.Value(consts.CtxClaims.Str()).(crypto.CustomClaims)
	if !ok {
		return nil, huma.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}
	resp, err := generic.DbFetchManyWithOffset[models.Session](uh.Service.ProvServ.GormConn, ctx, models.SessionFilter{UserId: v.UserId}, q.PaginationInput, &generic.Opt{Debug: false})
	if err != nil {
		return dtos.PHumaReturn(dtos.PResp[[]authDtos.SessionData]{}, err)
	}
	data := authDtos.SessionsToData(resp.Body)
	return dtos.PHumaReturn(dtos.PResp[[]authDtos.SessionData]{
		Body:         data,
		Status:       resp.Status,
		RowsAffected: resp.RowsAffected,
		Count:        resp.Count,
		HasMore:      resp.HasMore,
		HasPrev:      resp.HasPrev,
		Code:         resp.Code,
		Message:      resp.Message,
		Error:        resp.Error,
		// NextCursor:   resp.NextCursor,
		// PrevCursor:   resp.PrevCursor,
	}, nil)
}
