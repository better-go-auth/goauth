// Package humasso mounts the sso endpoints on a Huma API.
package humasso

import (
	"context"
	"encoding/json"
	"mime"
	"net/http"
	"net/url"

	autherr "github.com/better-go-auth/goauth/src/common/autherr"
	ssodtos "github.com/better-go-auth/goauth/src/plugins/sso/dtos"
	"github.com/better-go-auth/goauth/src/plugins/sso/services"
)

// Handler adapts the sso service to Huma.
type Handler struct {
	Service *services.Service
}

// NewHandler builds the handler.
func NewHandler(svc *services.Service) *Handler { return &Handler{Service: svc} }

// ─── outputs ─────────────────────────────────────────────────────────────────

type redirectOutput struct {
	Status    int
	Location  string        `header:"Location"`
	SetCookie []http.Cookie `header:"Set-Cookie"`
}

func redirect(r *services.Redirect) *redirectOutput {
	return &redirectOutput{Status: http.StatusFound, Location: r.Location, SetCookie: r.Cookies}
}

type rawOutput struct {
	Status      int
	ContentType string        `header:"Content-Type"`
	Location    string        `header:"Location"`
	SetCookie   []http.Cookie `header:"Set-Cookie"`
	Body        []byte
}

// ─── provider management ─────────────────────────────────────────────────────

type registerInput struct {
	Body ssodtos.SSORegisterInput
}

type providerOutput struct {
	Body *ssodtos.SSOProviderResponse
}

// Register is POST /sso/register.
func (h *Handler) Register(ctx context.Context, in *registerInput) (*providerOutput, error) {
	current := h.Service.Kit().Current(ctx)
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	res, err := h.Service.Register(ctx, current.User, in.Body)
	if err != nil {
		return nil, err
	}
	return &providerOutput{Body: res}, nil
}

type listOutput struct {
	Body *ssodtos.SSOListProvidersResponse
}

// ListProviders is GET /sso/providers.
func (h *Handler) ListProviders(ctx context.Context, _ *struct{}) (*listOutput, error) {
	current := h.Service.Kit().Current(ctx)
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	res, err := h.Service.ListProviders(ctx, current.User.ID)
	if err != nil {
		return nil, err
	}
	return &listOutput{Body: res}, nil
}

type getProviderInput struct {
	ProviderID string `query:"providerId" required:"true"`
}

type sanitizedOutput struct {
	Body *ssodtos.SSOSanitizedProvider
}

// GetProvider is GET /sso/get-provider.
func (h *Handler) GetProvider(ctx context.Context, in *getProviderInput) (*sanitizedOutput, error) {
	current := h.Service.Kit().Current(ctx)
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	res, err := h.Service.GetProvider(ctx, current.User.ID, in.ProviderID)
	if err != nil {
		return nil, err
	}
	return &sanitizedOutput{Body: res}, nil
}

type updateInput struct {
	Body ssodtos.SSOUpdateProviderInput
}

// UpdateProvider is POST /sso/update-provider.
func (h *Handler) UpdateProvider(ctx context.Context, in *updateInput) (*sanitizedOutput, error) {
	current := h.Service.Kit().Current(ctx)
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	res, err := h.Service.UpdateProvider(ctx, current.User.ID, in.Body)
	if err != nil {
		return nil, err
	}
	return &sanitizedOutput{Body: res}, nil
}

type providerIDInput struct {
	Body ssodtos.SSOProviderIDInput
}

type successOutput struct {
	Body ssodtos.SSOSuccessResponse
}

// DeleteProvider is POST /sso/delete-provider.
func (h *Handler) DeleteProvider(ctx context.Context, in *providerIDInput) (*successOutput, error) {
	current := h.Service.Kit().Current(ctx)
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	if err := h.Service.DeleteProvider(ctx, current.User.ID, in.Body.ProviderID); err != nil {
		return nil, err
	}
	return &successOutput{Body: ssodtos.SSOSuccessResponse{Success: true}}, nil
}

type domainTokenOutput struct {
	Status int
	Body   *ssodtos.SSODomainVerificationTokenResponse
}

// RequestDomainVerification is POST /sso/request-domain-verification (201).
func (h *Handler) RequestDomainVerification(ctx context.Context, in *providerIDInput) (*domainTokenOutput, error) {
	current := h.Service.Kit().Current(ctx)
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	res, err := h.Service.RequestDomainVerification(ctx, current.User.ID, in.Body.ProviderID)
	if err != nil {
		return nil, err
	}
	return &domainTokenOutput{Status: http.StatusCreated, Body: res}, nil
}

type noContentOutput struct {
	Status int
}

// VerifyDomain is POST /sso/verify-domain (204).
func (h *Handler) VerifyDomain(ctx context.Context, in *providerIDInput) (*noContentOutput, error) {
	current := h.Service.Kit().Current(ctx)
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	if err := h.Service.VerifyDomain(ctx, current.User.ID, in.Body.ProviderID); err != nil {
		return nil, err
	}
	return &noContentOutput{Status: http.StatusNoContent}, nil
}

// ─── POST /sign-in/sso ───────────────────────────────────────────────────────

type signInInput struct {
	Body ssodtos.SSOSignInInput
}

type startOutput struct {
	SetCookie []http.Cookie `header:"Set-Cookie"`
	Body      ssodtos.SSORedirectResponse
}

// SignIn answers {url, redirect} and sets the state (OIDC) or relay state (SAML) cookie.
func (h *Handler) SignIn(ctx context.Context, in *signInInput) (*startOutput, error) {
	// Step 1: client supplied redirect targets must be trusted (better-auth's originCheckMiddleware)
	kit := h.Service.Kit()
	for _, c := range []struct {
		url string
		err *autherr.AuthError
	}{
		{in.Body.CallbackURL, autherr.ErrInvalidCallbackURL},
		{in.Body.ErrorCallbackURL, autherr.ErrInvalidErrorCallbackURL},
		{in.Body.NewUserCallbackURL, autherr.ErrInvalidNewUserCallbackURL},
	} {
		if err := kit.CheckURL(ctx, c.url, c.err); err != nil {
			return nil, err
		}
	}
	// Step 2: run the flow
	res, err := h.Service.SignIn(ctx, in.Body)
	if err != nil {
		return nil, err
	}
	return &startOutput{SetCookie: res.Cookies, Body: res.Body}, nil
}

// ─── OIDC callbacks ──────────────────────────────────────────────────────────

type callbackInput struct {
	ProviderID       string `path:"providerId"`
	Code             string `query:"code"`
	State            string `query:"state" required:"true"`
	Error            string `query:"error"`
	ErrorDescription string `query:"error_description"`
}

func (h *Handler) callbackParams(ctx context.Context, in *callbackInput) services.CallbackParams {
	p := services.CallbackParams{Code: in.Code, State: in.State, Error: in.Error, ErrorDescription: in.ErrorDescription}
	if req := h.Service.Kit().Request(ctx); req != nil {
		q := req.URL.Query()
		p.HasError, p.HasErrorDescription = q.Has("error"), q.Has("error_description")
	}
	return p
}

// Callback is GET /sso/callback/{providerId}.
func (h *Handler) Callback(ctx context.Context, in *callbackInput) (*redirectOutput, error) {
	r, err := h.Service.Callback(ctx, in.ProviderID, h.callbackParams(ctx, in))
	if err != nil {
		return nil, err
	}
	return redirect(r), nil
}

type sharedCallbackInput struct {
	Code             string `query:"code"`
	State            string `query:"state" required:"true"`
	Error            string `query:"error"`
	ErrorDescription string `query:"error_description"`
}

// CallbackShared is GET /sso/callback (the shared redirectURI).
func (h *Handler) CallbackShared(ctx context.Context, in *sharedCallbackInput) (*redirectOutput, error) {
	p := h.callbackParams(ctx, &callbackInput{Code: in.Code, State: in.State, Error: in.Error, ErrorDescription: in.ErrorDescription})
	r, err := h.Service.CallbackShared(ctx, p)
	if err != nil {
		return nil, err
	}
	return redirect(r), nil
}

// ─── SAML endpoints ──────────────────────────────────────────────────────────

// formOrJSON decodes an application/x-www-form-urlencoded or JSON body into string fields.
func formOrJSON(contentType string, raw []byte) (map[string]string, bool) {
	out := map[string]string{}
	if len(raw) == 0 {
		return out, false
	}
	mt, _, _ := mime.ParseMediaType(contentType)
	if mt == "application/json" {
		var m map[string]any
		if json.Unmarshal(raw, &m) != nil {
			return out, false
		}
		for k, v := range m {
			if s, ok := v.(string); ok {
				out[k] = s
			}
		}
		return out, true
	}
	vals, err := url.ParseQuery(string(raw))
	if err != nil {
		return out, false
	}
	for k := range vals {
		out[k] = vals.Get(k)
	}
	return out, true
}

type samlCallbackInput struct {
	ProviderID  string `path:"providerId"`
	ContentType string `header:"Content-Type"`
	RawBody     []byte
}

type samlCallbackGetInput struct {
	ProviderID string `path:"providerId"`
	RelayState string `query:"RelayState"`
}

// SAMLCallbackGet is GET /sso/saml2/callback/{providerId}: a signed-in browser is sent to RelayState.
func (h *Handler) SAMLCallbackGet(ctx context.Context, in *samlCallbackGetInput) (*redirectOutput, error) {
	r, err := h.Service.SAMLCallbackGet(ctx, in.ProviderID, in.RelayState, h.Service.Kit().Current(ctx))
	if err != nil {
		return nil, err
	}
	return redirect(r), nil
}

// SAMLCallbackPost is POST /sso/saml2/callback/{providerId}.
func (h *Handler) SAMLCallbackPost(ctx context.Context, in *samlCallbackInput) (*redirectOutput, error) {
	body, _ := formOrJSON(in.ContentType, in.RawBody)
	r, err := h.Service.SAMLCallbackPost(ctx, in.ProviderID, body["SAMLResponse"], body["RelayState"])
	if err != nil {
		return nil, err
	}
	return redirect(r), nil
}

type acsInput struct {
	ProviderID  string `path:"providerId"`
	ContentType string `header:"Content-Type"`
	RawBody     []byte
}

// ACS is POST /sso/saml2/sp/acs/{providerId}.
func (h *Handler) ACS(ctx context.Context, in *acsInput) (*redirectOutput, error) {
	body, _ := formOrJSON(in.ContentType, in.RawBody)
	if _, ok := body["SAMLResponse"]; !ok {
		return nil, autherr.New("VALIDATION_ERROR", "[body.SAMLResponse] Invalid input: expected string, received undefined", http.StatusBadRequest)
	}
	r, err := h.Service.ACS(ctx, in.ProviderID, body["SAMLResponse"], body["RelayState"])
	if err != nil {
		return nil, err
	}
	return redirect(r), nil
}

type metadataInput struct {
	ProviderID string `query:"providerId" required:"true"`
	Format     string `query:"format" enum:"xml,json" default:"xml"`
}

// SPMetadata is GET /sso/saml2/sp/metadata.
func (h *Handler) SPMetadata(ctx context.Context, in *metadataInput) (*rawOutput, error) {
	doc, err := h.Service.SPMetadata(ctx, in.ProviderID)
	if err != nil {
		return nil, err
	}
	return &rawOutput{Status: http.StatusOK, ContentType: "application/xml", Body: doc}, nil
}

type sloInput struct {
	ProviderID   string `path:"providerId"`
	SAMLRequest  string `query:"SAMLRequest"`
	SAMLResponse string `query:"SAMLResponse"`
	RelayState   string `query:"RelayState"`
	SigAlg       string `query:"SigAlg"`
	Signature    string `query:"Signature"`
	ContentType  string `header:"Content-Type"`
	RawBody      []byte
}

// sloOutput turns an SLO result into a redirect or an HTML form.
func sloOutput(res *services.SLOResult) *rawOutput {
	if res.Redirect != nil {
		return &rawOutput{Status: http.StatusFound, Location: res.Redirect.Location, SetCookie: res.Redirect.Cookies}
	}
	return &rawOutput{Status: http.StatusOK, ContentType: "text/html", SetCookie: res.Cookies, Body: res.HTML}
}

type sloGetInput struct {
	ProviderID   string `path:"providerId"`
	SAMLRequest  string `query:"SAMLRequest"`
	SAMLResponse string `query:"SAMLResponse"`
	RelayState   string `query:"RelayState"`
	SigAlg       string `query:"SigAlg"`
	Signature    string `query:"Signature"`
}

// SLOGet is GET /sso/saml2/sp/slo/{providerId} (HTTP-Redirect binding).
func (h *Handler) SLOGet(ctx context.Context, in *sloGetInput) (*rawOutput, error) {
	return h.SLO(ctx, &sloInput{ProviderID: in.ProviderID, SAMLRequest: in.SAMLRequest, SAMLResponse: in.SAMLResponse, RelayState: in.RelayState, SigAlg: in.SigAlg, Signature: in.Signature})
}

// SLO is POST /sso/saml2/sp/slo/{providerId} (and the shared GET logic).
func (h *Handler) SLO(ctx context.Context, in *sloInput) (*rawOutput, error) {
	// Step 1: body values win over the query (HTTP-POST binding), else the HTTP-Redirect query
	body, _ := formOrJSON(in.ContentType, in.RawBody)
	p := services.SLOParams{SAMLRequest: in.SAMLRequest, SAMLResponse: in.SAMLResponse, RelayState: in.RelayState}
	if req := h.Service.Kit().Request(ctx); req != nil {
		p.Method, p.RawQuery = req.Method, req.URL.RawQuery
	}
	if v := body["SAMLRequest"]; v != "" {
		p.SAMLRequest, p.FromBody = v, true
	}
	if v := body["SAMLResponse"]; v != "" {
		p.SAMLResponse, p.FromBody = v, true
	}
	if v := body["RelayState"]; v != "" {
		p.RelayState = v
	}
	// Step 2: run the flow
	res, err := h.Service.HandleSLO(ctx, in.ProviderID, p, h.Service.Kit().Current(ctx))
	if err != nil {
		return nil, err
	}
	return sloOutput(res), nil
}

type initiateSLOInput struct {
	ProviderID string `path:"providerId"`
	Body       ssodtos.SSOInitiateSLOInput
}

// InitiateSLO is POST /sso/saml2/logout/{providerId}.
func (h *Handler) InitiateSLO(ctx context.Context, in *initiateSLOInput) (*redirectOutput, error) {
	current := h.Service.Kit().Current(ctx)
	if current == nil {
		return nil, autherr.ErrUnauthorized
	}
	r, err := h.Service.InitiateSLO(ctx, in.ProviderID, in.Body.CallbackURL, current)
	if err != nil {
		return nil, err
	}
	return redirect(r), nil
}
