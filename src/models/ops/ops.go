package ops

import (
	"github.com/better-go-auth/goauth/src/models"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/birukbelay/gocmn/src/consts"
)

const (
	OffsetPaginatedAdmins = consts.OperationId("Ad-1-OffsetPaginatedAdmins")
	GetOneAdminById       = consts.OperationId("Ad-2-GetOneAdminById")
	UpdateAdmin           = consts.OperationId("Ad-3-UpdateAdmin")
)

var PlatformAdminOperationMap = map[consts.OperationId]models.OperationAccess{
	OffsetPaginatedAdmins: {AllowedRoles: []string{enums.PLATFORM_ADMIN.S()}, Description: ""},
	GetOneAdminById:       {AllowedRoles: []string{enums.PLATFORM_ADMIN.S()}, Description: ".."},
	UpdateAdmin:           {AllowedRoles: []string{enums.PLATFORM_ADMIN.S()}, Description: ".."},
	//companies related
	OffsetPaginatedCompanies: {AllowedRoles: []string{enums.PLATFORM_ADMIN.S()}, Description: ""},
	GetOneCompanyById:        {AllowedRoles: []string{enums.PLATFORM_ADMIN.S()}, Description: ".."},
	UpdateCompany:            {AllowedRoles: []string{enums.PLATFORM_ADMIN.S()}, Description: ".."},
	ApproveCompany:           {AllowedRoles: []string{enums.PLATFORM_ADMIN.S()}, Description: ".."},
}

const (
	OffsetPaginatedCompanies = consts.OperationId("Ad_Cp-1-OffsetPaginatedCompanies")
	GetOneCompanyById        = consts.OperationId("Ad_Cp-2-GetOneCompanyById")
	UpdateCompany            = consts.OperationId("Ad_Cp-3-UpdateCompany")
	ApproveCompany           = consts.OperationId("Ad_Cp-4-ApproveCompany")
	// DisableCompany = consts.OperationId("Pr_1-DisableCompany")
	// OwnerCreateCompany       = consts.OperationId("Pr_1-GetMyProfile")
)

const (
	GetMySessions       = consts.OperationId("Se-1-GetMySessions")
	DeleteMySessionById = consts.OperationId("Ad-2-DeleteMySessionById")
	//
	GetUsersSessions   = consts.OperationId("Se-1-GetUsersSessions")
	DeleteUsersSession = consts.OperationId("Ad-3-DeleteUsersSession")
)

var SessionOperationMap = map[consts.OperationId]models.OperationAccess{
	GetMySessions:       {AllowedRoles: []string{}, Description: ""},
	DeleteMySessionById: {AllowedRoles: []string{}, Description: ".."},
	GetUsersSessions:    {AllowedRoles: []string{enums.PLATFORM_ADMIN.S()}, Description: ""},
	DeleteUsersSession:  {AllowedRoles: []string{enums.PLATFORM_ADMIN.S()}, Description: ".."},
}
