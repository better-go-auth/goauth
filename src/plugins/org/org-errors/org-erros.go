package orgerrors

import (
	"net/http"

	errors "github.com/better-go-auth/goauth/src/common/error"
)

const (
	OrgNotFound        = errors.RespCode("ORGANIZATION_NOT_FOUND")
	MemberNotFound     = errors.RespCode("MEMBER_NOT_FOUND")
	InvitationNotFound = errors.RespCode("INVITATION_NOT_FOUND")
	InvitationExpired  = errors.RespCode("INVITATION_EXPIRED")
	AlreadyMember      = errors.RespCode("ALREADY_A_MEMBER")
)

var (
	//Org Errors
	ErrOrgNotFound        = errors.New(OrgNotFound, OrgNotFound.Msg(), http.StatusNotFound)
	ErrMemberNotFound     = errors.New(MemberNotFound, MemberNotFound.Msg(), http.StatusNotFound)
	ErrInvitationNotFound = errors.New(InvitationNotFound, InvitationNotFound.Msg(), http.StatusNotFound)
	ErrAlreadyMember      = errors.New(AlreadyMember, AlreadyMember.Msg(), http.StatusBadRequest)
	ErrInvitationExpired  = errors.New(InvitationExpired, InvitationExpired.Msg(), http.StatusBadRequest)
)
