package orgerrors

import (
	"net/http"

	errors "github.com/better-go-auth/goauth/src/common/errors"
)

const (
	OrgNotFound        = errors.RespCode("ORGANIZATION_NOT_FOUND")
	MemberNotFound     = errors.RespCode("MEMBER_NOT_FOUND")
	InvitationNotFound = errors.RespCode("INVITATION_NOT_FOUND")
	InvitationExpired  = errors.RespCode("INVITATION_EXPIRED")
	AlreadyMember      = errors.RespCode("ALREADY_A_MEMBER")
	SlugTaken          = errors.RespCode("SLUG_TAKEN")
	OrgNotActive       = errors.RespCode("ORGANIZATION_NOT_ACTIVE")
	OrgPending         = errors.RespCode("ORGANIZATION_PENDING_APPROVAL")
	OrgSuspended       = errors.RespCode("ORGANIZATION_SUSPENDED")
)

var (
	// Org Errors
	ErrOrgNotFound        = errors.New(OrgNotFound, "Organization not found", http.StatusNotFound)
	ErrMemberNotFound     = errors.New(MemberNotFound, "Member not found in this organization", http.StatusNotFound)
	ErrInvitationNotFound = errors.New(InvitationNotFound, "Invitation not found", http.StatusNotFound)
	ErrAlreadyMember      = errors.New(AlreadyMember, "User is already a member of this organization", http.StatusBadRequest)
	ErrInvitationExpired  = errors.New(InvitationExpired, "This invitation has expired", http.StatusBadRequest)
	ErrSlugTaken          = errors.New(SlugTaken, "Organization slug is already taken", http.StatusUnprocessableEntity)
	ErrOrgNotActive       = errors.New(OrgNotActive, "Organization is not active", http.StatusForbidden)
	ErrOrgPending         = errors.New(OrgPending, "Organization is pending approval", http.StatusForbidden)
	ErrOrgSuspended       = errors.New(OrgSuspended, "Organization is suspended", http.StatusForbidden)
)
