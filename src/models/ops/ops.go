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

var PlatformAdminOperationMap = map[consts.OperationId]models.OperationAccessDto{
	OffsetPaginatedAdmins: {AllowedRoles: []string{enums.Admin.S()}, Description: ""},
	GetOneAdminById:       {AllowedRoles: []string{enums.Admin.S()}, Description: ".."},
	UpdateAdmin:           {AllowedRoles: []string{enums.Admin.S()}, Description: ".."},
	// //companies related
	// OffsetPaginatedCompanies: {AllowedRoles: []string{enums.Admin.S()}, Description: ""},
	// GetOneCompanyById:        {AllowedRoles: []string{enums.Admin.S()}, Description: ".."},
}

const (
	OffsetPaginatedCompanies = consts.OperationId("Ad_Cp-1-OffsetPaginatedCompanies")
	GetOneCompanyById        = consts.OperationId("Ad_Cp-2-GetOneCompanyById")
	UpdateCompany            = consts.OperationId("Ad_Cp-3-UpdateCompany")
	ApproveCompany           = consts.OperationId("Ad_Cp-4-ApproveCompany")
	// DisableCompany = consts.OperationId("Pr_1-DisableCompany")
	// OwnerCreateCompany       = consts.OperationId("Pr_1-GetMyProfile")
)
