package enums

//=========================

//=================================   USER Roles  ============================

type Role string

const (
	User  = Role("User")
	Admin = Role("Admin")
)

func (r Role) S() string {
	return string(r)
}

//=================================   !  AccountStatus  ============================

type AccountStatus string

const (
	AccountPendingVerification = AccountStatus("pending_verification")
	AccountActive              = AccountStatus("active")
	AccountDisabled            = AccountStatus("disabled") //when blocked by the admin
	AccountDeleted             = AccountStatus("deleted")  //When the user deletes his own account
)

func (r AccountStatus) S() string {
	return string(r)
}
