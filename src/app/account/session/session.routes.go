package session

import (
	"net/http"

	"github.com/birukbelay/gocmn/src/consts"
	"github.com/danielgtaylor/huma/v2"

	"github.com/better-go-auth/goauth/src/models/ops"
	"github.com/better-go-auth/goauth/src/providers"
)

type HumaSessionHandler struct {
	// CmnServ *gen.IGenericGormServ
	Service *Service
	// GHandler *generic.IGenericAuthController[models.Session, *models.SessionDto, models.SessionDto, models.SessionFilter, models.SessionQuery]
	// DbService *gen.IGenericGormServT[models.Session, models.SessionDto, models.LogTraceDto]
}

// NewLogTraceHandler creates a content handler from IContentService & Generic Gorm Service
func NewSessionHandler(serv *Service) *HumaSessionHandler {
	return &HumaSessionHandler{
		Service: serv,
	}
}

func SetupSessionRoutes(humaRouter huma.API, cmnServ *providers.IProviderS, serv *Service) {
	genericController := NewSessionHandler(serv)

	tags := []string{"01-session"}
	path := consts.ApiV1 + "/01-session"
	pathId := path + "/{id}"
	huma.Register(humaRouter, huma.Operation{
		OperationID: ops.GetMySessions.Str(),
		Description: "Get the users Sessions",
		Method:      http.MethodGet,
		Path:        path,
		Tags:        tags,
		Middlewares: huma.Middlewares{cmnServ.MiddleWare.Authenticate(), cmnServ.MiddleWare.Authorize(ops.GetMySessions, ops.SessionOperationMap[ops.GetMySessions].AllowedRoles)},
	}, genericController.GetMySession,
	)
	huma.Register(humaRouter, huma.Operation{
		OperationID: ops.DeleteMySessionById.Str(),
		Method:      http.MethodPost,
		Path:        pathId,
		Tags:        tags,
		Middlewares: huma.Middlewares{cmnServ.MiddleWare.Authenticate(), cmnServ.MiddleWare.Authorize(ops.DeleteMySessionById, ops.SessionOperationMap[ops.DeleteMySessionById].AllowedRoles)},
	}, genericController.DelteMySession,
	)
	// huma.Register(humaRouter, huma.Operation{
	// 	OperationID: ops.GetOneSession.Str(),
	// 	Method:      http.MethodGet,
	// 	Path:        pathId,
	// 	Tags:        tags,
	// 	Middlewares: huma.Middlewares{cmnServ.Authorization(ops.GetOneSession, ops.SessionOperationMap[ops.GetOneSession].AllowedRoles, nil)},
	// }, genericController.GHandler.AuthGetOneById,
	// )

}
