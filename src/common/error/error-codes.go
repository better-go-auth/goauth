package error



// Generic Http Status codes
const (
	// Success Messages

	Success       = RespCode("SUCCESS")        //200
	CreateSuccess = RespCode("CREATE_SUCCESS") //201
	UpdateSuccess = RespCode("UPDATE_SUCCESS") //201
	DeleteSuccess = RespCode("DELETE_SUCCESS") //204
	//HTTP CODES

	RecordNotFound = RespCode("NOT_FOUND")      //404
	BadRequest     = RespCode("BAD_REQUEST")    //400
	InternalError  = RespCode("INTERNAL_ERROR") //500

)

// Operation Messages
const (
	NoRecordsUpdated           = RespCode("NO_RECORDS_UPDATED")
	NoRecordsDeleted           = RespCode("NO_RECORDS_DELETED")
	UpdatingAssociationsFailed = RespCode("UPDATING_ASSOCIATIONS_FAILED")
	NotModified                = RespCode("NOT_MODIFIED")
	//model related

	UserNotCreated = RespCode("USER_NOT_CREATED")
	UserCreated    = RespCode("USER_CREATED")
	//Generic

	Generic = RespCode("SOME_THING_WRONG")
	FAIL    = RespCode("FAILURE")
)

// Validation errors
const (
	Validation   = RespCode("VALIDATION_ERROR")
	EmptyFilter  = RespCode("EMPTY_FILTER")
	EmptyBody    = RespCode("EMPTY_BODY")
	UnknownValue = RespCode("UNKNOWN_VALUE")
	InvalidData  = RespCode("INVALID_DATA")
)

// Auth Status Codes
const (
	PasswordDontMatch   = RespCode("PASSWORD_DONT_MATCH")
	InfoOrCode          = RespCode("INFO_OR_CODE_WRONG")
	CodeExpired         = RespCode("CODE_EXPIRED")
	InvalidEmailOrPhone = RespCode("INVALID_EMAIL_OR_PHONE")
	PhoneExists         = RespCode("PHONE_EXISTS")
	EmailExists         = RespCode("USER_ALREADY_EXISTS_USE_ANOTHER_EMAIL")
	Password            = RespCode("PASSWORD_NOT_STORED")
	CouldNotAssignRole  = RespCode("ROLE_NOT_ASSIGNED")
	TokenDontMatch      = RespCode("TOKEN_DONT_MATCH")

	// User Related Errors
	InvalidToken  = RespCode("INVALID_TOKEN")
	UserNotActive = RespCode("USER_NOT_ACTIVE")
	UserNotFound  = RespCode("USER_NOT_FOUND")
	UserExists    = RespCode("USER_EXISTS")

	// Predefined Auth Plugin Error Codes
	InvalidCredentials = RespCode("INVALID_EMAIL_OR_PASSWORD")
	EmailNotVerified   = RespCode("EMAIL_NOT_VERIFIED")
	UserBanned         = RespCode("USER_BANNED")
	Unauthorized       = RespCode("UNAUTHORIZED")
	Forbidden          = RespCode("FORBIDDEN")
	SlugTaken          = RespCode("SLUG_TAKEN")
	InvalidEmail       = RespCode("INVALID_EMAIL")
	SessionExpired     = RespCode("SESSION_EXPIRED")
	//Company
	InvitationExpired  = RespCode("INVITATION_EXPIRED")
	AlreadyMember      = RespCode("ALREADY_A_MEMBER")
	//not found
	SessionNotFound    = RespCode("SESSION_NOT_FOUND")
	ProviderNotFound   = RespCode("PROVIDER_NOT_FOUND")
	//pwd related
	PasswordTooLong  = RespCode("PASSWORD_TOO_LONG")
	PasswordTooShort = RespCode("PASSWORD_TOO_SHORT")
	WeakPassword     = RespCode("WEAK_PASSWORD")
	TokenExpired     = RespCode("TOKEN_EXPIRED")
	InvalidPassword  = RespCode("INVALID_PASSWORD")
	// feature toggles
	EmailAndPasswordDisabled             = RespCode("EMAIL_PASSWORD_DISABLED")
	EmailAndPasswordSignUpDisabled       = RespCode("EMAIL_PASSWORD_SIGN_UP_DISABLED")
	CredentialAccountNotFound            = RespCode("CREDENTIAL_ACCOUNT_NOT_FOUND")
	MethodNotAllowedDeferSessionRequired = RespCode("METHOD_NOT_ALLOWED_DEFER_SESSION_REQUIRED")
	AccountNotFound                      = RespCode("ACCOUNT_NOT_FOUND")
	FailedToUnlinkLastAccount            = RespCode("FAILED_TO_UNLINK_LAST_ACCOUNT")
	SessionNotFresh                      = RespCode("SESSION_NOT_FRESH")
	//
	OrgNotFound        = RespCode("ORGANIZATION_NOT_FOUND")
	MemberNotFound     = RespCode("MEMBER_NOT_FOUND")
	InvitationNotFound = RespCode("INVITATION_NOT_FOUND")
)

// Account Status Codes
const (
	AccountBanned    = RespCode("ACCOUNT_BANNED")
	Unlinked         = RespCode("UNLINKED")
	UnlinkNotAllowed = RespCode("UNLINK_NOT_ALLOWED")
	
)

// File related api responses
const (
	JsonUnmarshal = RespCode("JSON_UNMARSHAL_ERROR")
)

var (
	errorText = map[RespCode]string{
		//Success responses
		Success:       "Success",
		CreateSuccess: "Successfully Created Record",
		UpdateSuccess: "Successfully Updated Record",
		DeleteSuccess: "Successfully Deleted Record",
		//Generic error Responses
		Generic: "Some thing may be wrong please try again",
		FAIL:    "Operation Failed please try again",
		//validation error
		Validation:   "validation failed",
		UnknownValue: "this value is not expected",
		EmptyFilter:  "the filter is empty",
		EmptyBody:    "the request body is empty",
		//operation errors
		NoRecordsUpdated:           "NO records were Updated",
		NoRecordsDeleted:           "NO records were Deleted",
		UpdatingAssociationsFailed: "Updating Associated Records Failed",
		//status code messages
		RecordNotFound: "data not found",
		BadRequest:     "bad request",
		InternalError:  "An internal error occurred",
		//

		//Auth Messages

		InvalidEmailOrPhone: " please enter a valid email address or phone number",
		InfoOrCode:          "please enter valid code or info",
		InvalidData:         "This Data Is Invalid",
		PhoneExists:         "Phone Already Exists",
		EmailExists:         "User already exists. Use another email.",
		Password:            "Password Could not be stored",
		CouldNotAssignRole:  "could not assign role to the user",
		TokenDontMatch:      "the Token Doesnt match",
		UserNotFound:        "User not found",
		InvalidToken:        "Invalid token",

		// Predefined Auth Plugin Error Messages
		InvalidCredentials:                   "Invalid email or password",
		EmailNotVerified:                     "Email not verified",
		UserBanned:                           "This account has been banned",
		SessionNotFound:                      "Session not found",
		SessionExpired:                       "Session has expired",
		Unauthorized:                         "Unauthorized",
		Forbidden:                            "Forbidden",
		WeakPassword:                         "Password does not meet requirements",
		OrgNotFound:                          "Organization not found",
		MemberNotFound:                       "Member not found in this organization",
		AlreadyMember:                        "User is already a member of this organization",
		InvitationNotFound:                   "Invitation not found",
		InvitationExpired:                    "This invitation has expired",
		SlugTaken:                            "Organization slug is already taken",
		InvalidEmail:                         "Invalid email",
		PasswordTooShort:                     "Password too short",
		PasswordTooLong:                      "Password too long",
		ProviderNotFound:                     "Provider not found",
		TokenExpired:                         "Token expired",
		InvalidPassword:                      "Invalid password",
		EmailAndPasswordDisabled:             "Email and password is not enabled",
		EmailAndPasswordSignUpDisabled:       "Email and password sign up is not enabled",
		CredentialAccountNotFound:            "Credential account not found",
		MethodNotAllowedDeferSessionRequired: "POST method requires deferSessionRefresh to be enabled in session config",
		AccountNotFound:                      "Account not found",
		FailedToUnlinkLastAccount:            "You can't unlink your last account",
		SessionNotFresh:                      "Session is not fresh",

		//------------------------------ Entities -----------------
		UserCreated:    " User Created",
		UserNotCreated: "User Not Created",
		UserExists:     "This user already Exists",
		JsonUnmarshal:  "Json Unmarshal Response",
	}
)