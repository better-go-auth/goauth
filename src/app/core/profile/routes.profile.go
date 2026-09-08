package profile

import (
	"net/http"

	"github.com/birukbelay/gocmn/src/consts"
	"github.com/danielgtaylor/huma/v2"

	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/providers"
)

// HProfileHandler .
type HProfileHandler[T models.IntUsr] struct {
	CmnServ *providers.IProviderS
	Service *Service[T]
}

// NewProfileHandler creates a profile handler from ProfileService & Generic Gorm Service
func NewProfileHandler[T models.IntUsr](serv *providers.IProviderS, service *Service[T]) *HProfileHandler[T] {
	return &HProfileHandler[T]{CmnServ: serv, Service: service}
}

const (
	GetMyProfile      = consts.OperationId("Pr_1-GetMyProfile")
	UpdateMyProfile   = consts.OperationId("Pr_2-UpdateMyProfile")
	ChangeMyPwd       = consts.OperationId("Pr_3-ChangeMyPassword")
	ChangeEmailReq    = consts.OperationId("Pr_4-ChangeEmailReq")
	ChangeEmailVerify = consts.OperationId("Pr_5-ChangeEmailVerify")
)

var ProfilePermissionsMap = map[consts.OperationId]models.OperationAccessDto{
	GetMyProfile:    {AllowedRoles: []string{}, Description: "Creating A User"},
	UpdateMyProfile: {AllowedRoles: []string{}},
	ChangeMyPwd:     {AllowedRoles: []string{}},
}

func SetUserProfileRoutes(humaRouter huma.API, provServ *providers.IProviderS, profileServ *Service[models.User], conf config.GoAuthOptions) {
	adminHandler := NewProfileHandler(provServ, profileServ)
	tags := []string{"profile"}
	basePath := conf.BasePath
	if basePath == "" {
		basePath = "/api/auth"
	}
	path := basePath + "/profile"

	huma.Register(humaRouter, huma.Operation{
		OperationID: GetMyProfile.Str(),
		Method:      http.MethodGet,
		Path:        path,
		Tags:        tags,
		Middlewares: huma.Middlewares{provServ.MiddleWare.Authenticate(), provServ.MiddleWare.Authorize(GetMyProfile, ProfilePermissionsMap[GetMyProfile].AllowedRoles)},
	}, adminHandler.GetMyProfile)

	huma.Register(humaRouter, huma.Operation{
		OperationID: UpdateMyProfile.Str(),
		Method:      http.MethodPatch,
		Path:        path,
		Tags:        tags,
		Middlewares: huma.Middlewares{provServ.MiddleWare.Authenticate(), provServ.MiddleWare.Authorize(UpdateMyProfile, nil)},
	}, adminHandler.UpdateMyProfile)

	huma.Register(humaRouter, huma.Operation{
		OperationID: ChangeMyPwd.Str(),
		Method:      http.MethodPost,
		Path:        path + "/change_pwd",
		Tags:        tags,
		Middlewares: huma.Middlewares{provServ.MiddleWare.Authenticate(), provServ.MiddleWare.Authorize(ChangeMyPwd, nil)},
	}, adminHandler.UpdateMyPassword)

	huma.Register(humaRouter, huma.Operation{
		OperationID: ChangeEmailReq.Str(),
		Method:      http.MethodPost,
		Path:        path + "/change_email",
		Tags:        tags,
		Middlewares: huma.Middlewares{provServ.MiddleWare.Authenticate(), provServ.MiddleWare.Authorize(ChangeEmailReq, ProfilePermissionsMap[ChangeEmailReq].AllowedRoles)},
	}, adminHandler.UpdateMyEmailReq)

	huma.Register(humaRouter, huma.Operation{
		OperationID: ChangeEmailVerify.Str(),
		Method:      http.MethodPost,
		Path:        path + "/verify_change_email",
		Tags:        tags,
		Middlewares: huma.Middlewares{provServ.MiddleWare.Authenticate(), provServ.MiddleWare.Authorize(ChangeEmailVerify, ProfilePermissionsMap[ChangeEmailVerify].AllowedRoles)},
	}, adminHandler.VerifyMyChangeEmailReq)

}
