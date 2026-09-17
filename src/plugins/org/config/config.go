package config

import "context"

type OrgConfig struct {
	InvitaionConfig
}

type InvitaionConfig struct {
	SendOrgInvitation SendOrgInvitation
}

// SendOrgInvitation sends an organization invite email.
type SendOrgInvitation func(ctx context.Context, to, inviterName, orgName, inviteURL string) error
