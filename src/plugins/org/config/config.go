package config

import (
	"context"
	"time"
)

type OrgConfig struct {
	InvitaionConfig
	// Weither the org will be pending and needs to be approved by the admins after creation
	OrgNeedsApproval bool
}

type InvitaionConfig struct {
	SendOrgInvitation       SendOrgInvitation
	InvitationNeedsApproval bool
	InvitationExpiresIn     time.Duration
}

// SendOrgInvitation sends an organization invite email.
type SendOrgInvitation func(ctx context.Context, to, inviterName, orgName, inviteURL string) error
