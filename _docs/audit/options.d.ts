
type User = {}
type Session = {}

type StoreIdentifierOption = "plain" | "hashed" | {
    hash: (identifier: string) => Promise<string>;
};

type BetterAuthOptions = {
    /**
     * The name of your application. Used as a display name in contexts
     * where your app needs to be identified — for example, as the default
     * issuer name in authenticator apps when users set up 2FA/TOTP.
     *
     * Can also be set via the `APP_NAME` environment variable.
     *
     * @default "Better Auth"
     */
    appName?: string | undefined;
    /**
     * Base URL for the Better Auth. This is typically the
     * root URL where your application server is hosted.
     *
     * Can be configured as:
     * - A static string: `"https://myapp.com"`
     * - A dynamic config with allowed hosts for multi-domain deployments
     *
     * If not explicitly set, the system will check environment variables:
     * `BETTER_AUTH_URL`, `NEXT_PUBLIC_BETTER_AUTH_URL`, etc.
     *
     * @example
     * ```ts
     * // Static URL
     * baseURL: "https://myapp.com"
     *
     * // Dynamic with allowed hosts (for Vercel, multi-domain, etc.)
     * baseURL: {
     *   allowedHosts: ["myapp.com", "*.vercel.app", "preview-*.myapp.com"],
     *   fallback: "https://myapp.com"
     * }
     * ```
     */
    //   baseURL?: BaseURLConfig | undefined;
    /**
     * Base path for the Better Auth. This is typically
     * the path where the
     * Better Auth routes are mounted.
     *
     * @default "/api/auth"
     */
    basePath?: string | undefined;
    /**
     * The secret to use for encryption,
     * signing and hashing.
     *
     * By default Better Auth will look for
     * the following environment variables:
     * process.env.BETTER_AUTH_SECRET,
     * process.env.AUTH_SECRET
     * If none of these environment
     * variables are set,
     * it will default to
     * "better-auth-secret-123456789".
     *
     * on production if it's not set
     * it will throw an error.
     *
     * you can generate a good secret
     * using the following command:
     * @example
     * ```bash
     * openssl rand -base64 32
     * ```
     */
    secret?: string | undefined;
    /**
     * Versioned secrets for non-destructive secret rotation.
     * When set, encryption uses an envelope format with key IDs.
     * First entry is the current key used for new encryption.
     * Remaining entries are decryption-only (previous rotations).
     *
     * Can also be set via BETTER_AUTH_SECRETS env var:
     * `BETTER_AUTH_SECRETS=2:base64secret,1:base64secret`
     *
     * When set, `secret` is only used as legacy fallback
     * for decrypting bare-hex payloads that predate the envelope format.
     */
    secrets?: Array<{
        version: number;
        value: string;
    }> | undefined;
    /**
     * Database configuration
     */

    /**
       * Secondary storage configuration
       *
       * This is used to store session and rate limit data.
       */
    //   secondaryStorage?: SecondaryStorage | undefined;
    /**
     * Email verification configuration
     */
    emailVerification?: {
        /**
         * Send a verification email
         * @param data the data object
         * @param request the request object
         */
        sendVerificationEmail?: (
            /**
             * @param user the user to send the
             * verification email to
             * @param url the URL to send the verification email to
             * it contains the token as well
             * @param token the token to send the verification email to
             */
            data: {
                user: User;
                url: string;
                token: string;
            },
            /**
             * The request object
             */
            request?: Request) => Promise<void>;
        /**
         * Send a verification email automatically after sign up.
         *
         * - `true`: Always send verification email on sign up
         * - `false`: Never send verification email on sign up
         * - `undefined`: Follows `requireEmailVerification` behavior
         *
         * @default undefined
         */
        sendOnSignUp?: boolean;
        /**
         * Send a verification email automatically
         * on sign in when the user's email is not verified
         *
         * @default false
         */
        sendOnSignIn?: boolean;
        /**
         * Auto signin the user after they verify their email
         */
        autoSignInAfterVerification?: boolean;
        /**
         * Number of seconds the verification token is
         * valid for.
         * @default 3600 seconds (1 hour)
         */
        expiresIn?: number;
        /**
         * A function that is called before a user verifies their email
         * @param user the user that verified their email
         * @param request the request object
         */
        beforeEmailVerification?: (user: User, request?: Request) => Promise<void>;
        /**
         * A function that is called when a user's email is updated to verified
         * @param user the user that verified their email
         * @param request the request object
         */
        afterEmailVerification?: (user: User, request?: Request) => Promise<void>;
    } | undefined;
    /**
     * Email and password authentication
     */
    emailAndPassword?: {
        /**
         * Enable email and password authentication
         *
         * @default false
         */
        enabled: boolean;
        /**
         * Disable email and password sign up
         *
         * @default false
         */
        disableSignUp?: boolean;
        /**
         * Require email verification before a session
         * can be created for the user.
         *
         * if the user is not verified, the user will not be able to sign in
         * and on sign in attempts, the user will be prompted to verify their email.
         */
        requireEmailVerification?: boolean;
        /**
         * The maximum length of the password.
         *
         * @default 128
         */
        maxPasswordLength?: number;
        /**
         * The minimum length of the password.
         *
         * @default 8
         */
        minPasswordLength?: number;
        /**
         * send reset password
         */
        sendResetPassword?: (
            /**
             * @param user the user to send the
             * reset password email to
             * @param url the URL to send the reset password email to
             * @param token the token to send to the user (could be used instead of sending the url
             * if you need to redirect the user to custom route)
             */
            data: {
                user: User;
                url: string;
                token: string;
            },
            /**
             * The request object
             */
            request?: Request) => Promise<void>;
        /**
         * Number of seconds the reset password token is
         * valid for.
         * @default 1 hour (60 * 60)
         */
        resetPasswordTokenExpiresIn?: number;
        /**
         * A callback function that is triggered
         * when a user's password is changed successfully.
         */
        onPasswordReset?: (data: {
            user: User;
        }, request?: Request) => Promise<void>;
        /**
         * Password hashing and verification
         *
         * By default Scrypt is used for password hashing and
         * verification. You can provide your own hashing and
         * verification function. if you want to use a
         * different algorithm.
         */
        password?: {
            hash?: (password: string) => Promise<string>;
            verify?: (data: {
                hash: string;
                password: string;
            }) => Promise<boolean>;
        };
        /**
         * Automatically sign in the user after sign up
         *
         * @default true
         */
        autoSignIn?: boolean;
        /**
         * Whether to revoke all other sessions when resetting password
         * @default false
         */
        revokeSessionsOnPasswordReset?: boolean;
        /**
         * A callback function that is triggered when a user tries to sign up
         * with an email that already exists. Useful for notifying the existing user
         * that someone attempted to register with their email.
         *
         * This is only called when `requireEmailVerification: true` or `autoSignIn: false`.
         */
        onExistingUserSignUp?: (
            /**
             * @param user the existing user from the database
             */
            data: {
                user: User;
            }, request?: Request) => Promise<void>;
        /**
         * Build a custom synthetic user for email enumeration
         * protection. When a sign-up attempt is made with an
         * email that already exists, this function is called
         * to build the fake user response.
         *
         * Use this when plugins add fields to the user table
         * (e.g. admin plugin adds `role`, `banned`, etc.)
         * to ensure the fake response is indistinguishable
         * from a real sign-up.
         *
         * @example
         * ```ts
         * customSyntheticUser: ({ coreFields, additionalFields, id }) => ({
         *   ...coreFields,
         *   role: "user",
         *   banned: false,
         *   banReason: null,
         *   banExpires: null,
         *   ...additionalFields,
         *   id,
         * })
         * ```
         */
        customSyntheticUser?: (params: {
      /** Core user fields: name, email, emailVerified, image, createdAt, updatedAt */coreFields: {
            name: string;
            email: string;
            emailVerified: boolean;
            image: string | null;
            createdAt: Date;
            updatedAt: Date;
        }; /** Processed additional fields from options.user.additionalFields (with defaults applied) */
            additionalFields: Record<string, unknown>; /** Generated user ID */
            id: string;
        }) => Record<string, unknown>;
    } | undefined;
    /**
     * list of social providers
     */
    //   socialProviders?: SocialProviders | undefined;
    /**
     * List of Better Auth plugins
     */
    //   plugins?: ([] | BetterAuthPlugin[]) | undefined;
    /**
     * User configuration
     */
    //   user?: (BetterAuthDBOptions<"user", keyof BaseUser> & {
    user?: ({
        /**
         * Changing email configuration
         */
        changeEmail?: {
            /**
             * Enable changing email
             * @default false
             */
            enabled: boolean;
            /**
             * Send a confirmation email to the old email address when the user changes their email.
             * @param data the data object
             * @param request the request object
             */
            sendChangeEmailConfirmation?: (data: {
                user: User;
                newEmail: string;
                url: string;
                token: string;
            }, request?: Request) => Promise<void>;
            /**
             * Update the email without verification if the user is not verified.
             * @default false
             */
            updateEmailWithoutVerification?: boolean;
        };
        /**
         * User deletion configuration
         */
        deleteUser?: {
            /**
             * Enable user deletion
             */
            enabled?: boolean;
            /**
             * Send a verification email when the user deletes their account.
             *
             * if this is not set, the user will be deleted immediately.
             * @param data the data object
             * @param request the request object
             */
            sendDeleteAccountVerification?: (data: {
                user: User;
                url: string;
                token: string;
            }, request?: Request) => Promise<void>;
            /**
             * A function that is called before a user is deleted.
             *
             * to interrupt with error you can throw `APIError`
             */
            beforeDelete?: (user: User, request?: Request) => Promise<void>;
            /**
             * A function that is called after a user is deleted.
             *
             * This is useful for cleaning up user data
             */
            afterDelete?: (user: User, request?: Request) => Promise<void>;
            /**
             * The expiration time for the delete token.
             *
             * @default 1 day (60 * 60 * 24) in seconds
             */
            deleteTokenExpiresIn?: number;
        };
    }) | undefined;
    //   session?: (BetterAuthDBOptions<"session", keyof BaseSession> & {
    session?: ({
        /**
         * Expiration time for the session token. The value
         * should be in seconds.
         * @default 7 days (60 * 60 * 24 * 7)
         */
        expiresIn?: number;
        /**
         * How often the session should be refreshed. The value
         * should be in seconds.
         * If set 0 the session will be refreshed every time it is used.
         * @default 1 day (60 * 60 * 24)
         */
        updateAge?: number;
        /**
         * Disable session refresh so that the session is not updated
         * regardless of the `updateAge` option.
         *
         * @default false
         */
        disableSessionRefresh?: boolean;
        /**
         * Defer session refresh writes to POST requests.
         * When enabled, GET is read-only and POST performs refresh.
         * Useful for read-replica database setups.
         *
         * @default false
         */
        deferSessionRefresh?: boolean;
        /**
         * By default if secondary storage is provided
         * the session is stored in the secondary storage.
         *
         * Set this to true to store the session in the database
         * as well.
         *
         * Reads are always done from the secondary storage.
         *
         * @default false
         */
        storeSessionInDatabase?: boolean;
        /**
         * By default, sessions are deleted from the database when secondary storage
         * is provided when session is revoked.
         *
         * Set this to true to preserve session records in the database,
         * even if they are deleted from the secondary storage.
         *
         * @default false
         */
        preserveSessionInDatabase?: boolean;
        /**
         * Enable caching session in cookie
         */
        cookieCache?: {
            /**
             * max age of the cookie
             * @default 5 minutes (5 * 60)
             */
            maxAge?: number;
            /**
             * Enable caching session in cookie
             * @default false
             */
            enabled?: boolean;
            /**
             * Strategy for encoding/decoding cookie cache
             *
             * - "compact": Uses base64url encoding with HMAC-SHA256 signature (compact format, no JWT spec overhead)
             * - "jwt": Uses JWT with HMAC signature (no encryption, follows JWT spec)
             * - "jwe": Uses JWE (JSON Web Encryption) with A256CBC-HS512 and HKDF key derivation for secure encrypted tokens
             *
             * @default "compact"
             */
            strategy?: "compact" | "jwt" | "jwe";
            /**
             * Controls stateless cookie cache refresh behavior.
             *
             * When enabled, the cookie cache will be automatically refreshed before expiry
             * WITHOUT querying the database. This is essential for fully stateless or DB-less scenarios.
             *
             * - `false`: Disable automatic refresh. Cache is only invalidated when it reaches maxAge expiry.
             * - `true`: Enable automatic refresh with default settings (refreshes when 80% of maxAge is reached).
             * - `object`: Custom refresh configuration with either `updateAge` or `shouldRefresh` function
             *
             * Note: When the cache expires (reaches maxAge), it will attempt to fetch from database if available.
             * The refreshCache option is specifically for refreshing BEFORE expiry in a stateless manner.
             *
             * @default false
             */
            refreshCache?: boolean | {
                /**
                 * Time in seconds before expiry when the cache should be refreshed.
                 * For example, if maxAge is 300 (5 minutes) and updateAge is 60,
                 * the cache will be refreshed when it has 60 seconds left before expiry.
                 *
                 * @default 20% of maxAge
                 */
                updateAge?: number;
            };
            /**
             * Version of the cookie cache
             *
             * If a cookie cache version is changed, all existing cookie caches with the old version
             * will be invalidated.
             *
             * It can be a string or a function that returns a string or a promise that returns a string.
             * If it's a function, it will be called with the session and user data
             *
             * @default "1"
             */
            version?: string | ((session: Session & Record<string, any>, user: User & Record<string, any>) => string) | ((session: Session & Record<string, any>, user: User & Record<string, any>) => Promise<string>);
        };
        /**
         * The age of the session to consider it fresh.
         *
         * This is used to check if the session is fresh
         * for sensitive operations. (e.g. deleting an account)
         *
         * If the session is not fresh, the user should be prompted
         * to sign in again.
         *
         * If set to 0, the session will be considered fresh every time. (⚠︎ not recommended)
         *
         * @default 1 day (60 * 60 * 24)
         */
        freshAge?: number;
    }) | undefined;

    //   account?: (BetterAuthDBOptions<"account", keyof BaseAccount> & {
    account?: ({
        /**
         * When enabled (true), the user account data (accessToken, idToken, refreshToken, etc.)
         * will be updated on sign in with the latest data from the provider.
         *
         * @default true
         */
        updateAccountOnSignIn?: boolean;
        /**
         * Configuration for account linking.
         */
        accountLinking?: {
            /**
             * Enable account linking
             *
             * @default true
             */
            enabled?: boolean;
            /**
             * Disable implicit account linking on sign-in.
             *
             * When enabled, accounts will not be automatically linked
             * during OAuth sign-in, even if the email is verified or
             * the provider is trusted. Users must explicitly link
             * accounts using `linkSocial()` while authenticated.
             *
             * @default false
             */
            disableImplicitLinking?: boolean;
            /**
             * Require the existing local user row to have
             * `emailVerified: true` before implicit account linking
             * uses the IdP's `email_verified` claim as ownership
             * proof. Defaults to `true` so an attacker who
             * pre-registers an unverified account at a victim's
             * email cannot have the victim's OAuth identity linked
             * into the attacker-owned row on first sign-in. Set to
             * `false` for backward compatibility on apps whose
             * users sign up via OAuth without verifying their email
             * locally; understand the takeover risk before doing
             * so.
             *
             * @default true
             *
             * @deprecated The option will be removed on the next
             * minor; the gate will become unconditional.
             */
            requireLocalEmailVerified?: boolean;
            /**
             * List of trusted providers. Can be a static array or a function
             * that returns providers dynamically. The function is called
             * during context init (with `request` undefined) and again
             * on each request (with the incoming Request). It must be
             * resilient to `request` being undefined.
             *
             * @example
             * ```ts
             * trustedProviders: ["google", "github"]
             * ```
             *
             * @example
             * ```ts
             * trustedProviders: async (request) => {
             *   if (!request) return [];
             *   const providers = await getTrustedProvidersForTenant(request);
             *   return providers;
             * }
             * ```
             */
            //   trustedProviders?: Array<LiteralUnion<SocialProviderList[number] | "email-password", string>> | ((request?: Request | undefined) => Awaitable<Array<LiteralUnion<SocialProviderList[number] | "email-password", string>>>);
            /**
             * If enabled (true), this will allow users to manually linking accounts with different email addresses than the main user.
             *
             * @default false
             *
             * ⚠️ Warning: enabling this might lead to account takeovers, so proceed with caution.
             */
            allowDifferentEmails?: boolean;
            /**
             * If enabled (true), this will allow users to unlink all accounts.
             *
             * @default false
             */
            allowUnlinkingAll?: boolean;
            /**
             * When enabled, linking an account copies the provider's profile onto
             * the local user, matching the fields persisted on sign-up (`name`,
             * `image`, and any `mapProfileToUser` fields). The local `email` and
             * `emailVerified` are never changed, so a link cannot rebind the
             * account's identity.
             *
             * @default false
             */
            updateUserInfoOnLink?: boolean;
        };
        /**
         * Encrypt OAuth tokens
         *
         * By default, OAuth tokens (access tokens, refresh tokens, ID tokens) are stored in plain text in the database.
         * This poses a security risk if your database is compromised, as attackers could gain access to user accounts
         * on external services.
         *
         * When enabled, tokens are encrypted using AES-256-GCM before storage, providing protection against:
         * - Database breaches and unauthorized access to raw token data
         * - Internal threats from database administrators or compromised credentials
         * - Token exposure in database backups and logs
         * @default false
         */
        encryptOAuthTokens?: boolean;
        /**
         * Skip state cookie check
         *
         * ⚠︎ this has security implications and should only be enabled if you know what you are doing.
         * @default false
         */
        skipStateCookieCheck?: boolean;
        /**
         * Strategy for storing OAuth state
         *
         * - "cookie": Store state in an encrypted cookie (stateless)
         * - "database": Store state in the database
         *
         * @default "database" when `database` or `secondaryStorage` is configured, "cookie" otherwise
         */
        storeStateStrategy?: "database" | "cookie";
        /**
         * Store account data after oauth flow on a cookie
         *
         * This is useful for database-less flow
         *
         * @default false
         *
         * @note This is automatically set to true if you haven't passed a database
         */
        storeAccountCookie?: boolean;
    }) | undefined;
    //   verification?: (BetterAuthDBOptions<"verification", keyof BaseVerification> & {
    verification?: ({
        /**
         * disable cleaning up expired values when a verification value is
         * fetched
         */
        disableCleanup?: boolean;
        /**
         * How to store verification identifiers (tokens, OTPs, etc.)
         *
         * @example "hashed"
         *
         * @default "plain"
         */
        storeIdentifier?: StoreIdentifierOption | {
            default: StoreIdentifierOption;
            overrides?: Record<string, StoreIdentifierOption>;
        };
        /**
         * Store verification data in database even when secondary storage is configured.
         * @default false
         */
        storeInDatabase?: boolean;
    }) | undefined;
    /**
     * Additional trusted origins. By default, Better Auth trusts your
     * app's {@link baseURL}. Use this option to allow additional origins
     * (e.g. a separate frontend domain).
     *
     * Can be a static array, a function that returns origins dynamically,
     * or use wildcard patterns (e.g. `"https://*.example.com"`).
     *
     * @param request - The request object.
     * It'll be undefined if no request was
     * made. Like during a create context call
     * or `auth.api` call.
     *
     * Trusted origins will be dynamically
     * calculated based on the request.
     *
     * @example
     * ```ts
     * trustedOrigins: async (request) => {
     *   return [
     *    "https://better-auth.com",
     *    "https://*.better-auth.com",
     *    request.headers.get("x-custom-origin")
     *   ];
     * }
     * ```
     * @returns An array of trusted origins.
     */
    //   trustedOrigins?: (string[] | ((request?: Request | undefined) => Awaitable<(string | undefined | null)[]>)) | undefined;

    /**
     * API error handling
     */
    //   onAPIError?: {
    //     /**
    //      * Throw an error on API error
    //      *
    //      * @default false
    //      */
    //     throw?: boolean;
    //     /**
    //      * Custom error handler
    //      *
    //      * @param error
    //      * @param ctx - Auth context
    //      */
    //     onError?: (error: unknown, ctx: AuthContext) => void | Promise<void>;
    //     /**
    //      * The URL to redirect to on error
    //      *
    //      * When errorURL is provided, the error will be added to the URL as a query parameter
    //      * and the user will be redirected to the errorURL.
    //      *
    //      * @default - "/api/auth/error"
    //      */
    //     errorURL?: string;
    //     /**
    //      * Configure the default error page provided by Better-Auth
    //      * Start your dev server and go to /api/auth/error to see the error page.
    //      */
    //     // customizeDefaultErrorPage?: {
    //     //   colors?: {
    //     //     background?: string;
    //     //     foreground?: string;
    //     //     primary?: string;
    //     //     primaryForeground?: string;
    //     //     mutedForeground?: string;
    //     //     border?: string;
    //     //     destructive?: string;
    //     //     titleBorder?: string;
    //     //     titleColor?: string;
    //     //     gridColor?: string;
    //     //     cardBackground?: string;
    //     //     cornerBorder?: string;
    //     //   };
    //     //   size?: {
    //     //     radiusSm?: string;
    //     //     radiusMd?: string;
    //     //     radiusLg?: string;
    //     //     textSm?: string;
    //     //     text2xl?: string;
    //     //     text4xl?: string;
    //     //     text6xl?: string;
    //     //   };
    //     //   font?: {
    //     //     defaultFamily?: string;
    //     //     monoFamily?: string;
    //     //   };
    //     //   disableTitleBorder?: boolean;
    //     //   disableCornerDecorations?: boolean;
    //     //   disableBackgroundGrid?: boolean;
    //     // };
    //   } | undefined;
    /**
     * Hooks
     */
    //   hooks?: {
    //     /**
    //      * Before a request is processed
    //      */
    //     before?: AuthMiddleware;
    //     /**
    //      * After a request is processed
    //      */
    //     after?: AuthMiddleware;
    //   } | undefined;
    /**
     * Disabled paths
     *
     * Paths you want to disable.
     */
    disabledPaths?: string[] | undefined;
    /**
     * Telemetry configuration
     */
    telemetry?: {
        /**
         * Enable telemetry collection
         *
         * @default false
         */
        enabled?: boolean;
        /**
         * Enable debug mode
         *
         * @default false
         */
        debug?: boolean;
    } | undefined;
    /**
     * Experimental features
     */
    experimental?: {
        /**
         * Enable experimental joins for your database adapter.
         *
         * 	Please read the adapter documentation for more information regarding joins before enabling this.
         * 	Not all adapters support joins.
         *
         * @default false
         */
        joins?: boolean;
    }
}




/*
//   database?: (PostgresPool | MysqlPool | SqliteDatabase | Dialect | DBAdapterInstance | Database | DatabaseSync | D1Database | {
//     dialect: Dialect;
//     type: KyselyDatabaseType;
//     /**
//      * casing for table names
//      *
//      * @default "camel"
//      */
//     casing?: "snake" | "camel";
//     /**
//      * Enable debug logs for the adapter
//      *
//      * @default false
//      */
//     debugLogs?: DBAdapterDebugLogOption;
//     /**
//      * Whether to execute multiple operations in a transaction.
//      * If the database doesn't support transactions,
//      * set this to `false` and operations will be executed sequentially.
//      *
//      * @default false
//      */
//     transaction?: boolean;
//   } | {
//     /**
//      * Kysely instance
//      */
//     db: Kysely<any>;
//     /**
//      * Database type between postgres, mysql and sqlite
//      */
//     type: KyselyDatabaseType;
//     /**
//      * casing for table names
//      *
//      * @default "camel"
//      */
//     casing?: "snake" | "camel";
//     /**
//      * Enable debug logs for the adapter
//      *
//      * @default false
//      */
//     debugLogs?: DBAdapterDebugLogOption;
//     /**
//      * Whether to execute multiple operations in a transaction.
//      * If the database doesn't support transactions,
//      * set this to `false` and operations will be executed sequentially.
//      *
//      * @default false
//      */
//     transaction?: boolean;
//   }) | undefined;

