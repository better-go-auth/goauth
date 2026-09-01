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
)

func (uh *HumaSessionHandler) DelteMySession(ctx context.Context, dto *dtos.HumaInputId) (*dtos.HumaResponse[dtos.GResp[models.Session]], error) {
	v, ok := ctx.Value(consts.CtxClaims.Str()).(crypto.CustomClaims)
	if !ok {
		return nil, huma.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}
	session, err := generic.DbGetOne[models.Session](uh.Service.ProvServ.GormConn, ctx, models.SessionFilter{UserId: v.UserId, SessionId: dto.ID}, nil)
	if err != nil {
		return nil, huma.NewError(http.StatusNotFound, "Session NOt Found")
	}
	sessionDlt, err := generic.DbDeleteOneById[models.Session](uh.Service.ProvServ.GormConn, ctx, session.Body.ID, nil)
	return dtos.HumaReturnG(sessionDlt, err)
}

func (uh *HumaSessionHandler) GetMySession(ctx context.Context, q *models.SessionQuery) (*dtos.HumaResponse[dtos.PResp[[]models.Session]], error) {
	v, ok := ctx.Value(consts.CtxClaims.Str()).(crypto.CustomClaims)
	if !ok {
		return nil, huma.NewError(http.StatusUnauthorized, "The Token is Not Correct Form")
	}
	resp, err := generic.DbFetchManyWithOffset[models.Session](uh.Service.ProvServ.GormConn, ctx, models.SessionFilter{UserId: v.UserId}, q.PaginationInput, &generic.Opt{Debug: false})
	return dtos.PHumaReturn(resp, err)
}
