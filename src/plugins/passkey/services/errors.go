package services

import (
	"net/http"

	"github.com/better-go-auth/goauth/src/plugins/pluginkit"
)

// Error messages of better-auth's PASSKEY_ERROR_CODES (@better-auth/passkey 1.6.16).
const (
	MsgChallengeNotFound            = "Challenge not found"
	MsgNotAllowedToRegisterPasskey  = "You are not allowed to register this passkey"
	MsgFailedToVerifyRegistration   = "Failed to verify registration"
	MsgPasskeyNotFound              = "Passkey not found"
	MsgAuthenticationFailed         = "Authentication failed"
	MsgUnableToCreateSession        = "Unable to create session"
	MsgFailedToUpdatePasskey        = "Failed to update passkey"
	MsgPreviouslyRegistered         = "Previously registered"
	MsgRegistrationCancelled        = "Registration cancelled"
	MsgAuthCancelled                = "Auth cancelled"
	MsgUnknownError                 = "Unknown error"
	MsgSessionRequired              = "Passkey registration requires an authenticated session"
	MsgResolveUserRequired          = "Passkey registration requires either an authenticated session or a resolveUser callback when requireSession is false"
	MsgResolvedUserInvalid          = "Resolved user is invalid"
	codeChallengeNotFound           = "CHALLENGE_NOT_FOUND"
	codeNotAllowedToRegisterPasskey = "YOU_ARE_NOT_ALLOWED_TO_REGISTER_THIS_PASSKEY"
	codeFailedToVerifyRegistration  = "FAILED_TO_VERIFY_REGISTRATION"
	codePasskeyNotFound             = "PASSKEY_NOT_FOUND"
	codeAuthenticationFailed        = "AUTHENTICATION_FAILED"
	codeUnableToCreateSession       = "UNABLE_TO_CREATE_SESSION"
	codeFailedToUpdatePasskey       = "FAILED_TO_UPDATE_PASSKEY"
	codeSessionRequired             = "SESSION_REQUIRED"
	codeResolveUserRequired         = "RESOLVE_USER_REQUIRED"
	codeResolvedUserInvalid         = "RESOLVED_USER_INVALID"
)

// Errors returned by the passkey endpoints, with the status better-auth answers them with.
var (
	ErrChallengeNotFound = pluginkit.NewError(http.StatusBadRequest, codeChallengeNotFound, MsgChallengeNotFound)
	// ErrNotAllowedToRegisterPasskey is also better-auth's "forbidden" answer of update-passkey.
	ErrNotAllowedToRegisterPasskey = pluginkit.NewError(http.StatusUnauthorized, codeNotAllowedToRegisterPasskey, MsgNotAllowedToRegisterPasskey)
	// ErrRegistrationRejected is the 400 answer for a missing origin or an attestation statement that does not verify.
	ErrRegistrationRejected = pluginkit.NewError(http.StatusBadRequest, codeFailedToVerifyRegistration, MsgFailedToVerifyRegistration)
	// ErrRegistrationFailed is the 500 answer better-auth gives when @simplewebauthn throws during verification.
	ErrRegistrationFailed = pluginkit.NewError(http.StatusInternalServerError, codeFailedToVerifyRegistration, MsgFailedToVerifyRegistration)
	// ErrPasskeyUnknown is verify-authentication's 401 for an unregistered credential.
	ErrPasskeyUnknown = pluginkit.NewError(http.StatusUnauthorized, codePasskeyNotFound, MsgPasskeyNotFound)
	// ErrPasskeyNotFound is the 404 of update/delete for an unknown passkey ID.
	ErrPasskeyNotFound = pluginkit.NewError(http.StatusNotFound, codePasskeyNotFound, MsgPasskeyNotFound)
	// ErrAuthenticationUnverified is the 401 for an assertion whose signature does not verify.
	ErrAuthenticationUnverified = pluginkit.NewError(http.StatusUnauthorized, codeAuthenticationFailed, MsgAuthenticationFailed)
	// ErrAuthenticationFailed is the 400 for an assertion rejected by verification (challenge, origin, counter, ...).
	ErrAuthenticationFailed  = pluginkit.NewError(http.StatusBadRequest, codeAuthenticationFailed, MsgAuthenticationFailed)
	ErrUnableToCreateSession = pluginkit.NewError(http.StatusInternalServerError, codeUnableToCreateSession, MsgUnableToCreateSession)
	ErrFailedToUpdatePasskey = pluginkit.NewError(http.StatusInternalServerError, codeFailedToUpdatePasskey, MsgFailedToUpdatePasskey)
	ErrSessionRequired       = pluginkit.NewError(http.StatusUnauthorized, codeSessionRequired, MsgSessionRequired)
	ErrResolveUserRequired   = pluginkit.NewError(http.StatusBadRequest, codeResolveUserRequired, MsgResolveUserRequired)
	ErrResolvedUserInvalid   = pluginkit.NewError(http.StatusBadRequest, codeResolvedUserInvalid, MsgResolvedUserInvalid)
	// ErrOriginMissing is better-auth's `new APIError("BAD_REQUEST", { message: "origin missing" })`: a 400 whose
	// body is only {"message": "origin missing"} (no code, like better-call's APIError without one).
	ErrOriginMissing = pluginkit.NewError(http.StatusBadRequest, "", "origin missing")
	// ErrUserNotFound is verify-authentication's answer when the passkey's user no longer exists.
	ErrUserNotFound = pluginkit.NewError(http.StatusInternalServerError, "INTERNAL_SERVER_ERROR", "User not found")
	// ErrForbidden is requireResourceOwnership's plain UNAUTHORIZED (delete-passkey of another user's passkey).
	ErrForbidden = pluginkit.NewError(http.StatusUnauthorized, "UNAUTHORIZED", "Unauthorized")
	// ErrMissingID is requireResourceOwnership's answer for an empty id.
	ErrMissingID = pluginkit.NewError(http.StatusBadRequest, "BAD_REQUEST", "Missing required parameter: id")
)
