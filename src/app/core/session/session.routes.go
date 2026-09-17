package session

import (
	"net/http"

	"github.com/birukbelay/gocmn/src/consts"
	"github.com/danielgtaylor/huma/v2"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
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

const (
	GetMySessions       = consts.OperationId("Se-1-GetMySessions")
	DeleteMySessionById = consts.OperationId("Ad-2-DeleteMySessionById")
	//
	// GetUsersSessions   = consts.OperationId("Se-1-GetUsersSessions")
	// DeleteUsersSession = consts.OperationId("Ad-3-DeleteUsersSession")
)

var SessionOperationMap = map[consts.OperationId]models.OperationAccessDto{
	GetMySessions:       {AllowedRoles: []string{}, Description: ""},
	DeleteMySessionById: {AllowedRoles: []string{}, Description: ".."},
	// GetUsersSessions:    {AllowedRoles: []string{enums.Admin.S()}, Description: ""},
	// DeleteUsersSession:  {AllowedRoles: []string{enums.Admin.S()}, Description: ".."},
}

func SetupSessionRoutes(humaRouter huma.API, provServ *providers.IProviderS, serv *Service, conf config.AuthConfig) {
	genericController := NewSessionHandler(serv)

	tags := []string{"session"}
	basePath := conf.BasePath
	if basePath == "" {
		basePath = "/api/auth"
	}
	path := basePath + "/session"
	pathId := path + "/{id}"
	huma.Register(humaRouter, huma.Operation{
		OperationID: GetMySessions.Str(),
		Description: "Get the users Sessions",
		Method:      http.MethodGet,
		Path:        path,
		Tags:        tags,
		Middlewares: huma.Middlewares{provServ.MiddleWare.Authenticate(), provServ.MiddleWare.Authorize(GetMySessions, SessionOperationMap[GetMySessions].AllowedRoles)},
	}, genericController.GetMySession,
	)
	huma.Register(humaRouter, huma.Operation{
		OperationID: DeleteMySessionById.Str(),
		Method:      http.MethodPost,
		Path:        pathId,
		Tags:        tags,
		Middlewares: huma.Middlewares{provServ.MiddleWare.Authenticate(), provServ.MiddleWare.Authorize(DeleteMySessionById, SessionOperationMap[DeleteMySessionById].AllowedRoles)},
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
