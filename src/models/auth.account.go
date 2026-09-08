package models

import "time"

// Account stores OAuth provider accounts linked to a user.
// One user can have multiple accounts (e.g. google + github).
type Account struct {
	Base

	UserID string `json:"userId" gorm:"not null;index;size:26"       bun:"user_id,notnull"`
	User   *User  `json:"user,omitempty" gorm:"foreignKey:UserID"    bun:"rel:belongs-to,join:user_id=id"`

	// Provider info
	AccountID             string     `json:"accountId"          gorm:"not null;size:255"     bun:"account_id,notnull"` //this is the email or phone or etc
	ProviderId            Providers  `json:"providerId"         gorm:"not null;size:50"      bun:"provider_id,notnull"`
	AccessToken           *string    `json:"accessToken"        gorm:"type:text"             bun:"access_token"`
	RefreshToken          *string    `json:"refreshToken"       gorm:"type:text"             bun:"refresh_token"`
	AccessTokenExpiresAt  *time.Time `json:"accessTokenExpiresAt"                          bun:"access_token_expires_at"`
	RefreshTokenExpiresAt *time.Time `json:"refreshTokenExpiresAt"                        bun:"refresh_token_expires_at"`
	Scope                 *string    `json:"scope"              gorm:"size:1024"             bun:"scope"`
	IdToken               *string    `json:"idToken"            gorm:"type:text"             bun:"id_token"`
	Password              *string    `json:"password"           gorm:"type:text"             bun:"password"` // for email/password
}

type Providers string

const (
	// ProvCredential is Better Auth's providerId for email/password accounts.
	ProvCredential Providers = "credential"
	ProvPhone      Providers = "phone"
	ProvGoogle     Providers = "google"
	ProvGithub     Providers = "github"
	ProvTwitter    Providers = "twitter"
)

func (p Providers) S() string {
	return string(p)
}
func (Account) TableName() string { return "auth_accounts" }
