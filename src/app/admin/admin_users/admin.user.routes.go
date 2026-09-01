package admins

import (
	"net/http"

	"github.com/birukbelay/gocmn/src/consts"
	"github.com/birukbelay/gocmn/src/generic"
	"github.com/danielgtaylor/huma/v2"

	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/ops"
	"github.com/better-go-auth/goauth/src/providers"
)

type Service struct {
	ProvServ *providers.IProviderS
}

func NewService(genServ *providers.IProviderS) *Service {
	return &Service{
		ProvServ: genServ,
	}
}

type HumaHandler struct {
	Service  *Service
	GHandler *generic.IGenericController[models.User, models.UserDto, models.AdminUserUpdateDto, models.UserFilter, models.UserQuery]
}

func NewHandler(serv *Service) *HumaHandler {
	return &HumaHandler{
		Service:  serv,
		GHandler: generic.NewGenericController[models.User, models.UserDto, models.AdminUserUpdateDto, models.UserFilter, models.UserQuery](serv.ProvServ.GormConn)}
}
func SetupManageAdminUsersRoutes(humaRouter huma.API, cmnServ *providers.IProviderS, serv *Service) {
	genericController := NewHandler(serv)

	tags := []string{"2-admin"}
	path := consts.ApiV1 + "/02-admin"
	pathId := consts.ApiV1 + "/02-admin/{id}"
	huma.Register(humaRouter, huma.Operation{
		OperationID: ops.OffsetPaginatedAdmins.Str(),
		Description: "admins are platform admins and company owners",
		Method:      http.MethodGet,
		Path:        path,
		Tags:        tags,
		Middlewares: huma.Middlewares{cmnServ.MiddleWare.Authenticate(), cmnServ.MiddleWare.Authorize(ops.OffsetPaginatedAdmins, ops.PlatformAdminOperationMap[ops.OffsetPaginatedAdmins].AllowedRoles)},
	}, genericController.GHandler.OffsetPaginated,
	)
	huma.Register(humaRouter, huma.Operation{
		OperationID: ops.GetOneAdminById.Str(),
		Description: "admins are platform admins and company owners",
		Method:      http.MethodGet,
		Path:        pathId,
		Tags:        tags,
		Middlewares: huma.Middlewares{cmnServ.MiddleWare.Authenticate(), cmnServ.MiddleWare.Authorize(ops.GetOneAdminById, ops.PlatformAdminOperationMap[ops.GetOneAdminById].AllowedRoles)},
	}, genericController.GHandler.GetOneById,
	)

	//--------------
	huma.Register(humaRouter, huma.Operation{
		OperationID: ops.UpdateAdmin.Str(),
		Description: "admins are platform admins: use this route to update other admins info",
		Method:      http.MethodPatch,
		Path:        pathId,
		Tags:        tags,
		Middlewares: huma.Middlewares{cmnServ.MiddleWare.Authenticate(), cmnServ.MiddleWare.Authorize(ops.UpdateAdmin, ops.PlatformAdminOperationMap[ops.UpdateAdmin].AllowedRoles)},
	}, genericController.GHandler.UpdateOneById,
	)
}
