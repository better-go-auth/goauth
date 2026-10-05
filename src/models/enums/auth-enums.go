package enums

import "strings"

//=================================   USER Roles  ============================

// Role is a better-auth admin-plugin role; a user's role column may hold several, comma-separated ("admin,user").
type Role string

const (
	User  = Role("user")
	Admin = Role("admin")
)

func (r Role) S() string {
	return string(r)
}

// HasRole reports whether the comma-separated roles contain one of want (case-insensitive).
func HasRole(roles string, want ...string) bool {
	for _, r := range strings.Split(roles, ",") {
		r = strings.TrimSpace(r)
		for _, w := range want {
			if strings.EqualFold(r, w) {
				return true
			}
		}
	}
	return false
}

//=================================   !  AccountStatus  ============================

type AccountStatus string

const (
	AccountPendingVerification = AccountStatus("pending_verification")
	AccountActive              = AccountStatus("active")
	AccountDisabled            = AccountStatus("disabled") // when blocked by the admin
	AccountDeleted             = AccountStatus("deleted")  // When the user deletes his own account
)

func (r AccountStatus) S() string {
	return string(r)
}
