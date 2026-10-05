# 03 – Config

Rule: every better-auth option keeps its name (PascalCase) and meaning. Anything goauth adds goes into a
`GoAuth` sub-struct of the same section, so a reader can always tell which options are better-auth's.
Durations use `time.Duration` instead of seconds.

## Shape

```go
type AuthConfig struct {
    AppName        string
    BaseURL        string
    BasePath       string          // "/api/auth"
    Secret         string          // $BETTER_AUTH_SECRET
    TrustedOrigins []string
    DisabledPaths  []string

    EmailAndPassword  EmailAndPassword
    EmailVerification EmailVerification
    User              User
    Session           Session
    Account           Account
    Verification      Verification
    RateLimit         RateLimit
    Advanced          Advanced

    Hooks         Hooks           // later
    DatabaseHooks DatabaseHooks   // later

    GoAuth GoAuthOptions          // top-level goauth-only options
}
```

## Section by section

| Section | better-auth fields (kept identical) | `GoAuth` extension fields |
|---|---|---|
| top level | appName, baseURL, basePath, secret, trustedOrigins, disabledPaths | `Mode` (legacy/compat until step 7), `LegacyRoutes`, `BetterAuthRoutes` |
| `EmailAndPassword` | enabled, disableSignUp, requireEmailVerification, minPasswordLength, maxPasswordLength, autoSignIn, sendResetPassword, resetPasswordTokenExpiresIn, onPasswordReset, revokeSessionsOnPasswordReset, password{hash,verify}, onExistingUserSignUp, customSyntheticUser | `RehashPasswords`, `LegacyHash` (bcrypt for legacy-only deployments) |
| `EmailVerification` | sendVerificationEmail, sendOnSignUp, sendOnSignIn, autoSignInAfterVerification, expiresIn, beforeEmailVerification, afterEmailVerification | `CodeSender`, `CodeGenerator`, `CodeExpiresIn` (6-digit code flow) |
| `User` | modelName, fields, additionalFields, changeEmail{enabled, sendChangeEmailVerification}, deleteUser{enabled, sendDeleteAccountVerification, beforeDelete, afterDelete} | `SoftDelete`, `RequireActive` |
| `Session` | modelName, fields, expiresIn, updateAge, disableSessionRefresh, deferSessionRefresh, storeSessionInDatabase, preserveSessionInDatabase, freshAge, cookieCache{enabled, maxAge, strategy, version, refreshCache}, additionalFields | `HashTokens`, `SingleSession`, `JWT` (below) |
| `Account` | modelName, fields, accountLinking{…}, encryptOAuthTokens, storeAccountCookie, storeStateStrategy | — |
| `Verification` | modelName, fields, disableCleanup | — |
| `RateLimit` | enabled, window, max, customRules, storage, modelName | — |
| `Advanced` | cookiePrefix, useSecureCookies, crossSubDomainCookies{enabled, domain}, cookies, defaultCookieAttributes, disableCSRFCheck, disableOriginCheck, ipAddress{ipAddressHeaders, disableIpTracking, ipv6Subnet}, database{generateId} | `OverrideHumaErrors` |

### `Session.GoAuth.JWT` (replaces today's `SessionConfig` / `JwtVar`)

```go
type SessionJWT struct {
    Enabled          bool          // issue access/refresh tokens on legacy routes
    AccessSecret     string        // defaults to a key derived from Secret
    RefreshSecret    string        // defaults to a different derived key, never equal to AccessSecret
    AccessExpiresIn  time.Duration // 15m–60m
    RefreshExpiresIn time.Duration // ignored once refresh = session token (session lifetime applies)
    CheckRevocation  bool          // per-request session lookup for access tokens
}
```

## Migrating from today's config

`SetDefaults` maps old fields onto new ones for one minor version and logs a deprecation warning:

| Old | New |
|---|---|
| `SessionConfig.JwtVar.AccessSecret/RefreshSecret/…ExpireMin` | `Session.GoAuth.JWT.*` |
| `SessionConfig.CheckRevocationInDb` | `Session.GoAuth.JWT.CheckRevocation` |
| `SessionConfig.SingleSession` | `Session.GoAuth.SingleSession` |
| `SessionConfig.BlacklistPrefix/RevocationPrefix` | removed (revocation = delete session) |
| `EmailVerification.VerificationCodeSender/CodeGenerator/ExpiresIn` | `EmailVerification.GoAuth.*` |
| `Mode`, `Advanced.OverrideHumaErrors` | `GoAuth.Mode`, `Advanced.GoAuth.OverrideHumaErrors` |
