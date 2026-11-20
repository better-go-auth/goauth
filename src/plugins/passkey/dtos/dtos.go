// Package dtos holds the request and response bodies of the passkey endpoints. The option shapes match
// @simplewebauthn/server's PublicKeyCredentialCreationOptionsJSON / PublicKeyCredentialRequestOptionsJSON,
// which better-auth returns unchanged.
package dtos

import (
	"github.com/better-go-auth/goauth/src/models/dtos"
)

// RelyingParty is the `rp` member of registration options.
type RelyingParty struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

// UserEntity is the `user` member of registration options (id is base64url).
type UserEntity struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
}

// CredentialParameter is one entry of pubKeyCredParams.
type CredentialParameter struct {
	Alg  int    `json:"alg"`
	Type string `json:"type"`
}

// CredentialDescriptor is one entry of excludeCredentials / allowCredentials.
type CredentialDescriptor struct {
	ID         string   `json:"id"`
	Transports []string `json:"transports,omitempty"`
	Type       string   `json:"type"`
}

// AuthenticatorSelection is the authenticatorSelection member of registration options.
type AuthenticatorSelection struct {
	ResidentKey             string `json:"residentKey,omitempty"`
	UserVerification        string `json:"userVerification,omitempty"`
	AuthenticatorAttachment string `json:"authenticatorAttachment,omitempty"`
	RequireResidentKey      bool   `json:"requireResidentKey"`
}

// RegistrationOptions is the GET /passkey/generate-register-options response.
type RegistrationOptions struct {
	Challenge              string                 `json:"challenge"`
	RP                     RelyingParty           `json:"rp"`
	User                   UserEntity             `json:"user"`
	PubKeyCredParams       []CredentialParameter  `json:"pubKeyCredParams"`
	Timeout                int                    `json:"timeout"`
	Attestation            string                 `json:"attestation"`
	ExcludeCredentials     []CredentialDescriptor `json:"excludeCredentials"`
	AuthenticatorSelection AuthenticatorSelection `json:"authenticatorSelection"`
	Extensions             map[string]any         `json:"extensions"`
	Hints                  []string               `json:"hints"`
}

// AuthenticationOptions is the GET /passkey/generate-authenticate-options response.
type AuthenticationOptions struct {
	RPID             string                 `json:"rpId"`
	Challenge        string                 `json:"challenge"`
	AllowCredentials []CredentialDescriptor `json:"allowCredentials,omitempty"`
	Timeout          int                    `json:"timeout"`
	UserVerification string                 `json:"userVerification"`
	Extensions       map[string]any         `json:"extensions,omitempty"`
}

// VerifyRegistrationBody is the POST /passkey/verify-registration body. Response is the
// RegistrationResponseJSON produced by @simplewebauthn/browser's startRegistration.
type VerifyRegistrationBody struct {
	Response any     `json:"response,omitempty" required:"false"`
	Name     *string `json:"name,omitempty" required:"false" doc:"Name of the passkey"`
}

// VerifyAuthenticationBody is the POST /passkey/verify-authentication body (AuthenticationResponseJSON).
type VerifyAuthenticationBody struct {
	Response map[string]any `json:"response"`
}

// DeletePasskeyBody is the POST /passkey/delete-passkey body.
type DeletePasskeyBody struct {
	ID string `json:"id" doc:"The ID of the passkey to delete"`
}

// UpdatePasskeyBody is the POST /passkey/update-passkey body.
type UpdatePasskeyBody struct {
	ID   string `json:"id" doc:"The ID of the passkey which will be updated"`
	Name string `json:"name" doc:"The new name which the passkey will be updated to"`
}

// PasskeyStatusResponse is {"status": true}. The name is unique among goauth's
// plugins because Huma names OpenAPI schemas after the Go type.
type PasskeyStatusResponse struct {
	Status bool `json:"status"`
}

// StatusResponse is PasskeyStatusResponse (the name earlier goauth versions used).
type StatusResponse = PasskeyStatusResponse

// SessionResponse is the verify-authentication response {session, user}.
type SessionResponse = dtos.SessionWithUser
