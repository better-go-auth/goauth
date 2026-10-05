package models

import "time"

// Account is better-auth's `account` model: one row per sign-in method of a user
// (providerId "credential" holds the password hash; OAuth providers hold their tokens).
type Account struct {
	// ===== better-auth fields =====
	Base                             // id, createdAt, updatedAt
	AccountID             string     `json:"accountId"             gorm:"not null"           bun:"account_id,notnull"` // provider's user id; the user id for "credential"
	ProviderID            Providers  `json:"providerId"            gorm:"not null"           bun:"provider_id,notnull"`
	UserID                string     `json:"userId"                gorm:"not null;index"     bun:"user_id,notnull"`
	AccessToken           *string    `json:"accessToken"                    bun:"access_token"`
	RefreshToken          *string    `json:"refreshToken"                   bun:"refresh_token"`
	IDToken               *string    `json:"idToken"                        bun:"id_token"`
	AccessTokenExpiresAt  *time.Time `json:"accessTokenExpiresAt"                            bun:"access_token_expires_at"`
	RefreshTokenExpiresAt *time.Time `json:"refreshTokenExpiresAt"                           bun:"refresh_token_expires_at"`
	Scope                 *string    `json:"scope"                          bun:"scope"`
	Password              *string    `json:"password"                       bun:"password"`

	// ===== goauth fields (not in better-auth) =====
	User *User `json:"user,omitempty" gorm:"foreignKey:UserID" bun:"rel:belongs-to,join:user_id=id"`
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

func TimeNow() time.Time {
	return time.Now().UTC()
}
