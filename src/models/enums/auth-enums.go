package enums

//=========================

//=================================   USER Roles  ============================

type Role string

const (
	// General ROles
	UnverifiedUser = Role("UNVERIFIED_PERSON")

	//ADMIN ROLES
	PLATFORM_ADMIN = Role("PLATFORM_ADMIN") //to remove

	OWNER         = Role("OWNER")         //company Owner
	COMPANY_ADMIN = Role("COMPANY_ADMIN") //
	// //GENREAL Roles
	// USER = Role("USER") //unused

	//Company ROLES
	MANAGER   = Role("MANAGER")
	OPERATOR  = Role("OPERATOR")
	RESPONDER = Role("RESPONDER")
	CLIENT    = Role("CLIENT")
)

type GlobalRole string

const (
	ROLE_PLATFORM_ADMIN = GlobalRole("PLATFORM_ADMIN")
	ROLE_USER           = GlobalRole("USER")
)

func (r Role) S() string {
	return string(r)
}

//=================================   !  AccountStatus  ============================

type AccountStatus string

const (
	AccountPendingVerification = AccountStatus("pending_verification") //when it is pending email Verification
	AccountVerified            = AccountStatus("verified")             //email verified but needs to be accepted to a company

	AccountActive = AccountStatus("active")

	AccountDisabled = AccountStatus("disabled") //when it is Disabled by the admin

	AccountDeleted = AccountStatus("deleted") //When the user deletes his own account
)

func (r AccountStatus) S() string {
	return string(r)
}

type MembershipStatus string

const (
	MembershipPending = MembershipStatus("pending")
	MembershipActive  = MembershipStatus("active")
	MembershipBlocked = MembershipStatus("blocked")
)

//=================================   !  CompanyStatus  ============================

type CompanyStatus string

const (
	CompanyPendingApproval = CompanyStatus("pending_approval")
	CompanyApproved        = CompanyStatus("approved")
	CompanyDisabled        = CompanyStatus("disabled")
)


type MediaType string

const (
	MediaTypeImage    = MediaType("image")
	MediaTypeVideo    = MediaType("video")
	MediaTypeAudio    = MediaType("audio")
	MediaTypeDocument = MediaType("document")
)
