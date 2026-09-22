package consts

type OperationId string

func (o OperationId) Str() string {
	return string(o)
}

type ContextKey string

func (o ContextKey) Str() string {
	return string(o)
}

var (
	CtxClaims     = ContextKey("USER_CLAIMS")
	CTXCompany_ID = ContextKey("CTX_COMPANY_ID")
	CTXUser_ID    = ContextKey("CTX_USER_ID")
)

// AUTH_FIELD is the key used on the database
// type AUTH_FIELD string

// func (o AUTH_FIELD) S() string {
// 	return string(o)
// }

// var COMPANY_ID = AUTH_FIELD("company_id")
// var USER_ID = AUTH_FIELD("user_id")

const ApiV1 = "/api/v1"
