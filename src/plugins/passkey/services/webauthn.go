package services

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// supportedAlgorithms is @simplewebauthn/server's supportedCOSEAlgorithmIdentifiers: the credential key
// algorithms accepted at registration.
var supportedAlgorithms = []int{-8, -7, -36, -37, -38, -39, -257, -258, -259, -65535}

// defaultPubKeyCredParams is @simplewebauthn/server's defaultSupportedAlgorithmIDs (EdDSA, ES256, RS256).
var defaultPubKeyCredParams = []int{-8, -7, -257}

// errAttestationStatement marks a registration whose attestation statement did not verify
// (@simplewebauthn's `verified: false`), which better-auth answers with 400 instead of 500.
var errAttestationStatement = errors.New("passkey: attestation statement did not verify")

// errSignature marks an assertion whose signature did not verify (@simplewebauthn's `verified: false`),
// which better-auth answers with 401 instead of 400.
var errSignature = errors.New("passkey: assertion signature did not verify")

// registrationResult is @simplewebauthn's registrationInfo, reduced to what better-auth stores.
type registrationResult struct {
	CredentialID string
	PublicKey    []byte
	Counter      uint32
	AAGUID       string
	DeviceType   string
	BackedUp     bool
}

// verifyRegistration mirrors @simplewebauthn/server's verifyRegistrationResponse with
// requireUserVerification=false: client data type/challenge/origin, RP ID hash, user presence, key algorithm
// and the attestation statement.
func verifyRegistration(raw []byte, expectedChallenge string, expectedOrigins []string, rpID string) (*registrationResult, error) {
	// Step 1: parse the RegistrationResponseJSON (id/rawId/type checks, CBOR attestation object)
	pcc, err := protocol.ParseCredentialCreationResponseBytes(raw)
	if err != nil {
		return nil, err
	}
	cd := pcc.Response.CollectedClientData

	// Step 2: the client data origin must be one of the expected origins (exact match like @simplewebauthn)
	if !slices.Contains(expectedOrigins, cd.Origin) {
		return nil, fmt.Errorf("unexpected registration response origin %q, expected %v", cd.Origin, expectedOrigins)
	}

	// Step 3: the attested credential ID must be present
	att := pcc.Response.AttestationObject
	if len(att.AuthData.AttData.CredentialID) == 0 {
		return nil, errors.New("no credential ID was provided by authenticator")
	}
	if len(att.AuthData.AttData.CredentialPublicKey) == 0 {
		return nil, errors.New("no public key was provided by authenticator")
	}

	// Step 4: verify the client data (type, challenge), the authenticator data (RP ID hash, UP flag), the key
	// algorithm and the attestation statement
	params := make([]protocol.CredentialParameter, 0, len(supportedAlgorithms))
	for _, alg := range supportedAlgorithms {
		params = append(params, protocol.CredentialParameter{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.COSEAlgorithmIdentifier(alg)})
	}
	if _, err := pcc.Verify(expectedChallenge, rpID, []string{cd.Origin}, []string{cd.Origin}, nil, protocol.TopOriginImplicitVerificationMode, true, false, true, nil, params, protocol.AttestationPolicy{}, protocol.SignaturePolicy{}); err != nil {
		if isAttestationStatementError(err) {
			return nil, errors.Join(errAttestationStatement, err)
		}
		return nil, err
	}

	// Step 5: backup flags (a single-device credential cannot be backed up)
	deviceType, backedUp, err := backupFlags(att.AuthData.Flags)
	if err != nil {
		return nil, err
	}
	return &registrationResult{
		CredentialID: base64.RawURLEncoding.EncodeToString(att.AuthData.AttData.CredentialID),
		PublicKey:    att.AuthData.AttData.CredentialPublicKey,
		Counter:      att.AuthData.Counter,
		AAGUID:       formatAAGUID(att.AuthData.AttData.AAGUID),
		DeviceType:   deviceType,
		BackedUp:     backedUp,
	}, nil
}

// authenticationResult is @simplewebauthn's authenticationInfo.
type authenticationResult struct {
	NewCounter uint32
	DeviceType string
	BackedUp   bool
}

// verifyAuthentication mirrors @simplewebauthn/server's verifyAuthenticationResponse with
// requireUserVerification=false, including its signature counter rule.
func verifyAuthentication(raw []byte, expectedChallenge string, expectedOrigins []string, rpID string, publicKey []byte, storedCounter uint32) (*authenticationResult, error) {
	// Step 1: parse the AuthenticationResponseJSON
	par, err := protocol.ParseCredentialRequestResponseBytes(raw)
	if err != nil {
		return nil, err
	}
	cd := par.Response.CollectedClientData

	// Step 2: client data type, challenge and origin (exact origin match like @simplewebauthn)
	if !slices.Contains(expectedOrigins, cd.Origin) {
		return nil, fmt.Errorf("unexpected authentication response origin %q, expected %v", cd.Origin, expectedOrigins)
	}
	if err := cd.Verify(expectedChallenge, protocol.AssertCeremony, []string{cd.Origin}, []string{cd.Origin}, nil, protocol.TopOriginImplicitVerificationMode, true); err != nil {
		return nil, err
	}

	// Step 3: RP ID hash and user presence
	authData := par.Response.AuthenticatorData
	if err := authData.Verify(sha256Sum(rpID), nil, false, true); err != nil {
		return nil, err
	}

	// Step 4: the counter must grow unless both the stored and the reported counter are zero
	if (authData.Counter > 0 || storedCounter > 0) && authData.Counter <= storedCounter {
		return nil, fmt.Errorf("response counter value %d was lower than expected %d", authData.Counter, storedCounter)
	}

	// Step 5: backup flags
	deviceType, backedUp, err := backupFlags(authData.Flags)
	if err != nil {
		return nil, err
	}

	// Step 6: the signature over authData || sha256(clientDataJSON) must verify with the stored key
	if err := par.Verify(expectedChallenge, rpID, "", []string{cd.Origin}, []string{cd.Origin}, nil, protocol.TopOriginImplicitVerificationMode, true, false, true, publicKey, protocol.SignaturePolicy{}); err != nil {
		var perr *protocol.Error
		if errors.As(err, &perr) && perr.Type == protocol.ErrAssertionSignature.Type {
			return nil, errors.Join(errSignature, err)
		}
		return nil, err
	}
	return &authenticationResult{NewCounter: authData.Counter, DeviceType: deviceType, BackedUp: backedUp}, nil
}

// isAttestationStatementError reports whether err came from the attestation statement verification.
func isAttestationStatementError(err error) bool {
	var perr *protocol.Error
	if !errors.As(err, &perr) {
		return false
	}
	return perr.Type == protocol.ErrInvalidAttestation.Type || perr.Type == protocol.ErrAttestationCertificate.Type
}

// backupFlags is @simplewebauthn's parseBackupFlags.
func backupFlags(flags protocol.AuthenticatorFlags) (deviceType string, backedUp bool, err error) {
	backedUp = flags.HasBackupState()
	deviceType = "singleDevice"
	if flags.HasBackupEligible() {
		deviceType = "multiDevice"
	}
	if deviceType == "singleDevice" && backedUp {
		return "", false, errors.New("single-device credential indicated that it was backed up")
	}
	return deviceType, backedUp, nil
}

// formatAAGUID is @simplewebauthn's convertAAGUIDToString ("adce0002-35bc-c60a-648b-0b25f1f05503").
func formatAAGUID(aaguid []byte) string {
	h := hex.EncodeToString(aaguid)
	if len(h) != 32 {
		return h
	}
	return strings.Join([]string{h[0:8], h[8:12], h[12:16], h[16:20], h[20:32]}, "-")
}

// decodeStoredPublicKey decodes the stored publicKey (better-auth's base64.decode accepts both alphabets).
func decodeStoredPublicKey(s string) ([]byte, error) {
	s = strings.TrimRight(s, "=")
	if strings.ContainsAny(s, "-_") {
		return base64.RawURLEncoding.DecodeString(s)
	}
	return base64.RawStdEncoding.DecodeString(s)
}

// sha256Sum returns the SHA-256 hash of s (the expected rpIdHash).
func sha256Sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}
