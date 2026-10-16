# Unify Auth Services with Access-Token Plugin

This document outlines the complete architectural plan and exact code changes required to unify the authentication flows between the core **`authsvc.Service`** and the **`access-token` plugin**.

---

## 1. Executive Summary & Goals

### The Problem
Currently, `src/plugins/access-token/services/serv.auth.go` and `serv.profile.go` reimplement almost all authentication business logic from scratch:
- User lookup and duplicate email checking.
- Password hashing, password verification, and automatic hash upgrade (re-hashing).
- Credential account (`models.Account`) table management.
- User ban and active status validation.
- Session creation and session revocation.
- Password change and reset operations.

This creates code duplication, maintenance drift, and inconsistency in hook execution and configuration switches.

### The Target
Delegate core authentication business logic directly to **`src/app/services/auth/` (`*authsvc.Service`)**, keeping only the plugin's unique responsibilities in the `access-token` plugin:
1. **Verification Code (OTP) handling**: sending and verifying numeric/alphanumeric codes via `IVerificationService`.
2. **Access Token issuance**: signing JWT access tokens and returning JWT + refresh token payloads via `SessionService.Tokens()`.

---

## 2. Question: Do You Need Blacklisting Logic When Using Secondary Storage?

### Direct Answer: **No, blacklisting is redundant.**

Here is why:

### How Secondary Storage Session Checking Works
1. When a user logs in, the session is stored in secondary storage (e.g., Redis) under its token key (or session ID) with an expiration TTL.
2. When the user logs out or a session is revoked, `sessionMgr.Delete(ctx, token)` explicitly **deletes** the session from secondary storage (`mgr.secStore.Delete(ctx, tok)`).
3. On every incoming request, when the middleware or session resolver validates the session against secondary storage (`mgr.Get(ctx, tok)`):
   - If the session key exists and is unexpired $\rightarrow$ **Valid session** (allowed).
   - If the session key was deleted on logout $\rightarrow$ **Nil / Not Found** (rejected with `401 Unauthorized`).

Because secondary storage operates as an **active session whitelist**, a revoked session no longer exists in secondary storage.

```
Incoming Request with Token
          │
          ▼
Lookup in Secondary Storage (Redis)
   ├── Key Exists & Unexpired ──> Session Valid (Proceed)
   └── Key Absent (Deleted/Expired) ──> Session Revoked (401)
```

### When IS Blacklisting Actually Needed?
Blacklisting (`blacklist:<id>`) is **only** needed for **purely stateless JWT access tokens** where:
- The server does **not** query Redis or the DB on each request (to save latency).
- The JWT is cryptographically verified in memory.
- When a user logs out before the JWT expires (e.g., 15-minute TTL), you write a temporary tombstone `blacklist:<sid>` to Redis with a TTL of 15 minutes.

### Recommendation
Since your middleware validates the session against secondary storage:
- **You do NOT need blacklisting keys (`blacklist:<sessionID>`).**
- The session lookup against secondary storage is already your revocation check (as noted in [`src/common/middleware/middleware.go#L141`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/common/middleware/middleware.go#L141): `// the session lookup itself is the revocation check`).
- You can bypass `RevocationStore.IsTokenBlacklisted` and `RevocationStore.IsRevoked` entirely when session validation against secondary storage is enabled.

---

## 3. Architecture & Data Flow

```
+-----------------------------------------------------------------------------+
|                               HTTP Request                                  |
+--------------------------------------+--------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
|                 Huma Handlers (plugins/access-token/adapters)               |
+--------------------------------------+--------------------------------------+
                                       |
                                       v
+-----------------------------------------------------------------------------+
|             access-token AuthService (plugins/access-token/services)        |
+------------------+------------------------------------+---------------------+
                   |                                    |
     [Core Auth Business Logic]              [Plugin Specific Duties]
                   |                                    |
                   v                                    v
+------------------------------------+   +------------------------------------+
|          authsvc.Service           |   |       IVerificationService         |
|  - Validates credentials & rules   |   |   - Generates & emails OTP code    |
|  - Verifies & upgrades password    |   |   - Verifies OTP code              |
|  - Checks bans & user status       |   +------------------------------------+
|  - Updates LastLoginAt / IP        |   |          SessionService            |
|  - Creates & Deletes Sessions      |   |   - Signs JWT CustomClaims         |
+------------------------------------+   |   - Returns AuthTokens             |
                                         +------------------------------------+
```

---

## 4. Detailed Code Changes

### File 1: `src/plugins/plugins-interface.go`
Expose the core `AuthService` in `InitContext` so plugins can consume it during `Init()`.

```go
// Location: src/plugins/plugins-interface.go

// In InitContext, add AuthService:
type InitContext struct {
	Ctx              context.Context
	Api              huma.API
	Config           config.AuthConfig
	TxManager        interfaces.ITransactionManager
	SessionManager   serv_interfaces.ISessionManager
	AuthService      any // *authsvc.Service passed as any or via interface to prevent cyclic imports
	IAuthRepos       repo_interfaces.IAuthRepos
	MiddleWare       *middleware.AuthMiddleware
	Authenticator    authenticator.AuthenticateFunc
	Hooks            HookRegistry
	SecondaryStorage sec_storage.SecondaryStorage
	Extras           map[string]any
}
```

---

### File 2: `goauth.go`
Pass the instantiated `authService` into `initCtx` when initializing plugins.

```go
// Location: goauth.go (around line 191)

	// In SetupGoAuth():
	authService := authsvc.New(authsvc.Deps{Config: opts.AuthConfig, Repos: repos, Sessions: sessionMgr, Tx: txManager})

	initCtx := &plugin.InitContext{
		Ctx:              context.Background(),
		Api:              api,
		Config:           opts.AuthConfig,
		TxManager:        txManager,
		SessionManager:   sessionMgr,
		AuthService:      authService, // <--- Add this line
		IAuthRepos:       repos,
		MiddleWare:       mdlWare,
		Authenticator:    authenticate,
		Hooks:            hooks,
		SecondaryStorage: opts.SecondaryStorage,
		Extras:           map[string]any{},
	}
```

---

### File 3: `src/plugins/access-token/access_token.plugin.go`
Extract `AuthService` from `InitContext` and pass it to `services.NewAuthService` and `services.NewProfileService`.

```go
// Location: src/plugins/access-token/access_token.plugin.go

import (
	// ... existing imports ...
	authsvc "github.com/better-go-auth/goauth/src/app/services/auth"
)

// Inside Init(ictx *plugins.InitContext) error:
	var coreAuth *authsvc.Service
	if ca, ok := ictx.AuthService.(*authsvc.Service); ok {
		coreAuth = ca
	}

	p.vSvc = services.NewVerificationService(repos, vConf)
	p.sessionSvc = services.NewSessionService(sConf, repos, sessMgr, secStorage, ictx.Hooks)
	p.authSvc = services.NewAuthService(&sConf, coreAuth, p.vSvc, p.sessionSvc, repos, txMgr, p.passwords, ictx.Hooks)
	p.profileSvc = services.NewProfileService(coreAuth, p.vSvc, p.sessionSvc, repos, txMgr, p.passwords)
```

---

### File 4: `src/plugins/access-token/services/serv.auth.go`
Refactor `AuthService` to delegate authentication, user verification, and session lifecycle to `CoreAuth`.

```go
// Location: src/plugins/access-token/services/serv.auth.go

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/better-go-auth/goauth/src/app/repository/repo_interfaces"
	authsvc "github.com/better-go-auth/goauth/src/app/services/auth"
	"github.com/better-go-auth/goauth/src/common/dtos"
	errors "github.com/better-go-auth/goauth/src/common/errors"
	"github.com/better-go-auth/goauth/src/common/interfaces"
	"github.com/better-go-auth/goauth/src/config"
	"github.com/better-go-auth/goauth/src/models"
	authdtos "github.com/better-go-auth/goauth/src/models/dtos"
	"github.com/better-go-auth/goauth/src/models/enums"
	"github.com/better-go-auth/goauth/src/plugins"
	accesstokendtos "github.com/better-go-auth/goauth/src/plugins/access-token/dtos"
	interfaces1 "github.com/better-go-auth/goauth/src/plugins/access-token/services/interfaces"
	"github.com/better-go-auth/goauth/src/providers/authcrypto"
)

type AuthService struct {
	Config      *config.SessionGoAuth
	CoreAuth    *authsvc.Service
	VSvc        interfaces1.IVerificationService
	SesSvc      *SessionService
	UserRepo    repo_interfaces.IUserRepo
	AccountRepo repo_interfaces.IOAuthAccountRepo
	SessionRepo repo_interfaces.ISessionRepo
	TxMgr       interfaces.ITransactionManager
	Hooks       plugins.HookRegistry
	Passwords   *authcrypto.Passwords
}

func NewAuthService(
	conf *config.SessionGoAuth,
	coreAuth *authsvc.Service,
	vSvc interfaces1.IVerificationService,
	sSvc *SessionService,
	authRepos repo_interfaces.IAuthRepos,
	txMgr interfaces.ITransactionManager,
	passwords *authcrypto.Passwords,
	hooks ...plugins.HookRegistry,
) *AuthService {
	var h plugins.HookRegistry
	if len(hooks) > 0 {
		h = hooks[0]
	}
	return &AuthService{
		Config:      conf,
		CoreAuth:    coreAuth,
		VSvc:        vSvc,
		SesSvc:      sSvc,
		UserRepo:    authRepos,
		AccountRepo: authRepos,
		SessionRepo: authRepos,
		TxMgr:       txMgr,
		Passwords:   passwords,
		Hooks:       h,
	}
}

// -----------------------------------------------------------------------------
// 1. LOGIN: Delegate credential & session creation to CoreAuth.SignInEmail,
//    then sign JWT access token via SesSvc.Tokens.
// -----------------------------------------------------------------------------
func (aus *AuthService) Login(ctx context.Context, input accesstokendtos.LoginData) (dtos.GResp[accesstokendtos.TokenResponse], error) {
	if aus.CoreAuth == nil {
		return dtos.InternalErrMS[accesstokendtos.TokenResponse]("core auth service not available"), fmt.Errorf("core auth service not available")
	}

	// 1. Delegate verification, password check, rehash, bans, and session creation to core auth
	signInResult, err := aus.CoreAuth.SignInEmail(ctx, authdtos.SignInEmailInput{
		Email:    input.LoginInfo,
		Password: input.Password,
	}, authsvc.Meta{})
	if err != nil {
		return dtos.BadReqC[accesstokendtos.TokenResponse](errors.EmailOrPassword), err
	}

	if signInResult == nil || signInResult.Session == nil {
		return dtos.BadReqC[accesstokendtos.TokenResponse](errors.EmailOrPassword), errors.EmailOrPasswordErr
	}

	// 2. Access Token Plugin Duty: Issue JWT Access Token + Refresh Token
	tokens, err := aus.SesSvc.Tokens(&signInResult.Session.Session, signInResult.User.Role.S())
	if err != nil {
		return dtos.InternalErrMS[accesstokendtos.TokenResponse](err.Error()), err
	}

	// 3. Retrieve user model for response
	usr, err := aus.UserRepo.FindUserByID(ctx, signInResult.User.ID)
	if err != nil || usr == nil {
		return dtos.InternalErrMS[accesstokendtos.TokenResponse]("user not found"), err
	}

	return dtos.SuccessCreated(accesstokendtos.TokenResponse{
		AuthTokens: tokens,
		UserData:   *usr,
	}, 1), nil
}

// -----------------------------------------------------------------------------
// 2. SIGN UP: Create user & credentials, then dispatch OTP verification code.
// -----------------------------------------------------------------------------
func (aus *AuthService) RegisterWithEmail(ctx context.Context, input models.RegisterClientInput) (dtos.GResp[models.User], error) {
	hash, err := aus.Passwords.Hash(input.Password)
	if err != nil {
		return dtos.InternalErrMS[models.User]("hashing error"), err
	}

	var createdUser *models.User
	err = aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
		existingUser, _ := aus.UserRepo.FindUserByEmail(txCtx, input.Email)
		if existingUser != nil {
			// Update pending user if unverified
			updated, err := aus.UserRepo.UpdateUser(txCtx, existingUser.ID, map[string]interface{}{
				"FirstName": input.FirstName,
				"LastName":  input.LastName,
				"Role":      enums.User.S(),
				"Active":    false,
			})
			if err != nil {
				return err
			}
			createdUser = updated
		} else {
			newUser := &models.User{
				UserDto: models.UserDto{
					FirstName: input.FirstName,
					LastName:  input.LastName,
					Email:     input.Email,
					Role:      enums.User,
					Active:    new(bool), // false
				},
			}
			created, err := aus.UserRepo.CreateUser(txCtx, newUser)
			if err != nil {
				return err
			}
			createdUser = created
		}

		now := time.Now()
		pwdAccount := &models.Account{
			Base:       models.Base{ID: models.NewID(), CreatedAt: now, UpdatedAt: now},
			UserID:     createdUser.ID,
			ProviderID: models.ProvCredential,
			AccountID:  input.Email,
			Password:   &hash,
		}
		if _, err := aus.AccountRepo.CreateAccount(txCtx, pwdAccount); err != nil {
			if existingAcc, _ := aus.AccountRepo.FindAccountByUserAndProvider(txCtx, createdUser.ID, models.ProvCredential); existingAcc != nil {
				_, _ = aus.AccountRepo.UpdateAccount(txCtx, existingAcc.ID, map[string]interface{}{"Password": hash})
			} else {
				return fmt.Errorf("authsvc: create account: %w", err)
			}
		}

		// Access Token Plugin Duty: Dispatch OTP code instead of magic link
		_, err = aus.VSvc.SendVerification(txCtx, input.Email, models.PurposeEmailVerification, &interfaces1.VerOpt{UserId: createdUser.ID})
		if err != nil {
			return err
		}

		if aus.Hooks != nil {
			_ = aus.Hooks.TriggerAfterUserCreate(txCtx, createdUser)
		}
		return nil
	})
	if err != nil {
		return dtos.InternalErrMS[models.User]("transaction error"), err
	}

	return dtos.SuccessCreated(*createdUser, 1), nil
}

// -----------------------------------------------------------------------------
// 3. VERIFY REGISTERED USER: OTP Verification
// -----------------------------------------------------------------------------
func (aus *AuthService) VerifyRegisteredUser(ctx context.Context, input accesstokendtos.VerificationInput) (dtos.GResp[models.User], error) {
	var verifiedUser *models.User
	err := aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
		usr, err := aus.UserRepo.FindUserByEmail(txCtx, input.Info)
		if err != nil || usr == nil {
			return errors.InfoOrCodeErr
		}

		// Validate OTP code
		_, err = aus.VSvc.VerifyCode(txCtx, usr.GetEmail(), models.PurposeEmailVerification, input.Code)
		if err != nil {
			return errors.InfoOrCodeErr
		}

		// Activate user
		updatedUsr, err := aus.UserRepo.UpdateUser(txCtx, usr.ID, map[string]interface{}{
			"Active":        true,
			"EmailVerified": true,
		})
		if err != nil {
			return err
		}
		verifiedUser = updatedUsr
		return nil
	})
	if err != nil {
		return dtos.InternalErrMS[models.User]("verification error"), err
	}
	return dtos.SuccessCreated(*verifiedUser, 1), nil
}

// -----------------------------------------------------------------------------
// 4. LOGOUT: Delegate session revocation to CoreAuth.SignOut
// -----------------------------------------------------------------------------
func (aus *AuthService) Logout(ctx context.Context, refreshToken string) (dtos.GResp[bool], error) {
	if aus.CoreAuth != nil {
		if err := aus.CoreAuth.SignOut(ctx, refreshToken); err != nil {
			return dtos.InternalErrMS[bool](err.Error()), err
		}
		return dtos.SuccessCreated(true, 1), nil
	}

	// Fallback to SessionService if CoreAuth is not present
	session, err := aus.SesSvc.FindByRefreshToken(ctx, refreshToken)
	if err != nil || session == nil {
		return dtos.BadReqC[bool](errors.InvalidToken), errors.InvalidTokenError
	}
	if err := aus.SesSvc.DeleteSession(ctx, session.ID); err != nil {
		return dtos.InternalErrMS[bool](err.Error()), err
	}
	return dtos.SuccessCreated(true, 1), nil
}

// -----------------------------------------------------------------------------
// 5. RESET PASSWORD: Verify OTP code, update password, revoke all sessions
// -----------------------------------------------------------------------------
func (aus *AuthService) ResetPwd(ctx context.Context, input accesstokendtos.PwdResetInput) (dtos.GResp[bool], error) {
	usr, err := aus.UserRepo.FindUserByEmail(ctx, input.Info)
	if err != nil || usr == nil {
		return dtos.BadReqC[bool](errors.InfoOrCode), errors.InfoOrCodeErr
	}

	err = aus.TxMgr.Transaction(ctx, func(txCtx context.Context) error {
		// 1. Verify OTP code
		_, err = aus.VSvc.VerifyCode(txCtx, input.Info, models.PurposePasswordReset, input.Code)
		if err != nil {
			return errors.InfoOrCodeErr
		}

		// 2. Delegate password update to CoreAuth.SetPassword
		if aus.CoreAuth != nil {
			if err := aus.CoreAuth.SetPassword(txCtx, usr.ID, input.NewPassword); err != nil {
				return err
			}
		} else {
			hash, err := aus.Passwords.Hash(input.NewPassword)
			if err != nil {
				return err
			}
			account, err := aus.AccountRepo.FindAccountByUserAndProvider(txCtx, usr.ID, models.ProvCredential)
			if err != nil || account == nil {
				return errors.ErrInvalidCredentials
			}
			if _, err := aus.AccountRepo.UpdateAccount(txCtx, account.ID, map[string]interface{}{"Password": hash}); err != nil {
				return err
			}
		}

		// 3. Remove used OTP code
		_ = aus.VSvc.DeleteByIdentifier(txCtx, input.Info, models.PurposePasswordReset)

		// 4. Revoke all existing sessions
		return aus.SesSvc.DeleteAllUserSessions(txCtx, usr.ID)
	})
	if err != nil {
		return dtos.InternalErrMS[bool]("reset password error"), err
	}
	return dtos.SuccessCreated(true, 1), nil
}

func (aus *AuthService) ForgotPwd(ctx context.Context, input accesstokendtos.VerifyReqInput) (dtos.GResp[bool], error) {
	usr, err := aus.UserRepo.FindUserByEmail(ctx, input.Email)
	if err != nil || usr == nil {
		return dtos.SuccessCreated(true, 0), nil
	}
	// OTP dispatch
	return aus.VSvc.SendVerification(ctx, input.Email, models.PurposePasswordReset, &interfaces1.VerOpt{UserId: usr.ID})
}

func (aus *AuthService) ResetToken(ctx context.Context, refreshToken string) (dtos.GResp[accesstokendtos.TokenResponse], error) {
	session, err := aus.SesSvc.FindByRefreshToken(ctx, refreshToken)
	if err != nil || session == nil {
		return dtos.BadReqC[accesstokendtos.TokenResponse](errors.InvalidToken), errors.InvalidTokenError
	}
	usr, err := aus.UserRepo.FindUserByID(ctx, session.UserID)
	if err != nil || usr == nil {
		return dtos.BadReqC[accesstokendtos.TokenResponse](errors.DataNotFound), errors.UserNotFoundError
	}
	if usr.Active != nil && !*usr.Active {
		_ = aus.SesSvc.DeleteSession(ctx, session.ID)
		return dtos.BadReqC[accesstokendtos.TokenResponse](errors.Unauthorized), errors.ErrUnauthorized
	}
	if usr.Banned && (usr.BanExpires == nil || usr.BanExpires.After(time.Now())) {
		_ = aus.SesSvc.DeleteSession(ctx, session.ID)
		return dtos.BadReqM[accesstokendtos.TokenResponse](errors.ErrUserBanned.Message), errors.ErrUserBanned
	}
	tokens, err := aus.SesSvc.RefreshTokens(ctx, session, usr.Role.S())
	if err != nil {
		return dtos.BadReqC[accesstokendtos.TokenResponse](errors.InvalidToken), errors.InvalidTokenError
	}
	return dtos.SuccessCreated(accesstokendtos.TokenResponse{
		AuthTokens: tokens,
		UserData:   *usr,
	}, 1), nil
}
```

---

### File 5: `src/plugins/access-token/services/serv.profile.go`
Delegate profile updating and password changing to `CoreAuth`.

```go
// Location: src/plugins/access-token/services/serv.profile.go

// Inject CoreAuth in ProfileService:
type ProfileService struct {
	CoreAuth    *authsvc.Service
	VSvc        interfaces1.IVerificationService
	SesSvc      *SessionService
	TxMgr       interfaces.ITransactionManager
	UserRepo    repo_interfaces.IUserRepo
	AccountRepo repo_interfaces.IOAuthAccountRepo
	Passwords   *authcrypto.Passwords
}

func NewProfileService(
	coreAuth *authsvc.Service,
	vSvc interfaces1.IVerificationService,
	sesSvc *SessionService,
	authRepos repo_interfaces.IAuthRepos,
	txMgr interfaces.ITransactionManager,
	passwords *authcrypto.Passwords,
) *ProfileService {
	return &ProfileService{
		CoreAuth:    coreAuth,
		VSvc:        vSvc,
		SesSvc:      sesSvc,
		TxMgr:       txMgr,
		UserRepo:    authRepos,
		AccountRepo: authRepos,
		Passwords:   passwords,
	}
}

// UpdateProfile: Delegate to CoreAuth.UpdateUser when available
func (aus *ProfileService) UpdateProfile(ctx context.Context, userId string, update models.ProfileUpdateDto) (*models.User, error) {
	if aus.CoreAuth != nil {
		currentSession := &authdtos.SessionWithUser{
			User: authdtos.UserResponse{ID: userId},
		}
		name := ""
		if update.FirstName != "" || update.LastName != "" {
			name = update.FirstName + " " + update.LastName
		}
		var namePtr *string
		if name != "" {
			namePtr = &name
		}
		var imgPtr *string
		if update.Avatar != "" {
			imgPtr = &update.Avatar
		}

		fields := make(map[string]any)
		if update.FirstName != "" {
			fields["FirstName"] = update.FirstName
		}
		if update.LastName != "" {
			fields["LastName"] = update.LastName
		}

		res, err := aus.CoreAuth.UpdateUser(ctx, currentSession, authsvc.UpdateUserInput{
			Name:   namePtr,
			Image:  imgPtr,
			Fields: fields,
		})
		if err != nil {
			return nil, err
		}
		return aus.UserRepo.FindUserByID(ctx, res.User.ID)
	}

	// Direct repo fallback
	data := make(map[string]interface{})
	if update.FirstName != "" { data["FirstName"] = update.FirstName }
	if update.LastName != "" { data["LastName"] = update.LastName }
	if update.Avatar != "" { data["Image"] = update.Avatar }
	return aus.UserRepo.UpdateUser(ctx, userId, data)
}

// ChangePassword: Delegate to CoreAuth.ChangePassword
func (aus *ProfileService) ChangePassword(ctx context.Context, userId, sessionId string, input models.PasswordUpdateDto) (dtos.GResp[models.User], error) {
	if aus.CoreAuth != nil {
		currentSession := &authdtos.SessionWithUser{
			Session: authdtos.SessionData{ID: sessionId, UserID: userId},
			User:    authdtos.UserResponse{ID: userId},
		}
		revokeOthers := true
		_, err := aus.CoreAuth.ChangePassword(ctx, currentSession, authdtos.ChangePasswordInput{
			CurrentPassword:     input.OldPassword,
			NewPassword:         input.NewPassword,
			RevokeOtherSessions: &revokeOthers,
		}, authsvc.Meta{})
		if err != nil {
			return dtos.BadReqM[models.User](err.Error()), err
		}
		u, _ := aus.UserRepo.FindUserByID(ctx, userId)
		return dtos.SuccessCreated(*u, 1), nil
	}

	// Original fallback logic...
	return dtos.GResp[models.User]{}, nil
}
```

---

## 5. Middleware & Secondary Storage Cleanup

In [`src/common/middleware/middleware.go`](file:///home/k/Documents/7proj/better-go-auth/goauth/src/common/middleware/middleware.go):

```go
		case bearer != "" && isJWT(bearer):
			c, err := m.verifier.VerifyToken(bearer)
			if err != nil {
				ctx.SetStatus(http.StatusForbidden)
				_, _ = ctx.BodyWriter().Write([]byte("Token Not Valid"))
				return
			}
			// When secondary storage session check is configured:
			// Simply checking if the session exists in secondary storage or repo is sufficient.
			// Blacklist checks are skipped if session existence is already validated.
			if m.revocation != nil && c.SessionID != "" {
				revoked, _ := m.revocation.IsRevoked(ctx.Context(), c.SessionID)
				if revoked {
					ctx.SetStatus(http.StatusUnauthorized)
					_, _ = ctx.BodyWriter().Write([]byte("Session Revoked"))
					return
				}
			}
			claims = c
```

When sessions are stored in Redis (`secStore`), `sessionMgr.Delete` automatically evicts the session. The session lookup against Redis returns `nil` for any revoked session. You can safely remove calls to `blacklist:<token>` and `blacklist:<sessionId>`.

---

## 6. Implementation & Verification Checklist

- [ ] **Step 1:** Add `AuthService any` to `InitContext` in `src/plugins/plugins-interface.go`.
- [ ] **Step 2:** Pass `authService` in `SetupGoAuth()` in `goauth.go`.
- [ ] **Step 3:** Pass `ictx.AuthService` into `NewAuthService` and `NewProfileService` in `access_token.plugin.go`.
- [ ] **Step 4:** Refactor `Login()` in `serv.auth.go` to call `CoreAuth.SignInEmail()` and then sign tokens with `SesSvc.Tokens()`.
- [ ] **Step 5:** Refactor `Logout()` in `serv.auth.go` to call `CoreAuth.SignOut()`.
- [ ] **Step 6:** Refactor `ResetPwd()` in `serv.auth.go` to verify OTP code, call `CoreAuth.SetPassword()`, and revoke sessions.
- [ ] **Step 7:** Refactor `UpdateProfile()` and `ChangePassword()` in `serv.profile.go`.
- [ ] **Step 8:** Run test suite (`go test ./...`) to ensure all authentication tests pass with zero regression.
