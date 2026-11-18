-- goauth schema, postgres, desired state. Generated from goauth's schema registry (core models,
-- additionalFields and plugin schemas); regenerate instead of editing.

CREATE TABLE "users" (
  "id" text NOT NULL PRIMARY KEY,
  "name" text NOT NULL,
  "email" text NOT NULL,
  "emailVerified" boolean NOT NULL DEFAULT false,
  "image" text,
  "createdAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "role" text,
  "banned" boolean DEFAULT false,
  "banReason" text,
  "banExpires" timestamptz,
  "phoneNumber" text,
  "phoneNumberVerified" boolean,
  "twoFactorEnabled" boolean DEFAULT false,
  "username" text,
  "displayUsername" text,
  "isAnonymous" boolean DEFAULT false,
  "firstName" text,
  "lastName" text,
  "displayName" text,
  "bio" text,
  "dateOfBirth" timestamptz,
  "gender" text,
  "locale" text DEFAULT 'en',
  "timezone" text,
  "lastLoginIP" text,
  "lastLoginAt" timestamptz,
  "lastSeen" timestamptz,
  "deletedAt" timestamptz,
  "loyaltyTier" text NOT NULL DEFAULT 'bronze',
  "score" double precision,
  "tags" jsonb
);

CREATE TABLE "session" (
  "id" text NOT NULL PRIMARY KEY,
  "expiresAt" timestamptz NOT NULL,
  "token" text NOT NULL,
  "createdAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" timestamptz NOT NULL,
  "ipAddress" text,
  "userAgent" text,
  "userId" text NOT NULL,
  "impersonatedBy" text,
  "activeOrganizationId" text,
  "activeTeamId" text,
  "activeOrganizationType" text,
  "activeOrganizationRole" text,
  "deviceToken" text,
  "deviceId" text,
  "deviceName" text,
  "deviceType" text,
  "lastUsedAt" timestamptz,
  CONSTRAINT "fk_session_user_id" FOREIGN KEY ("userId") REFERENCES "users" ("id") ON DELETE CASCADE
);

CREATE TABLE "account" (
  "id" text NOT NULL PRIMARY KEY,
  "accountId" text NOT NULL,
  "providerId" text NOT NULL,
  "userId" text NOT NULL,
  "accessToken" text,
  "refreshToken" text,
  "idToken" text,
  "accessTokenExpiresAt" timestamptz,
  "refreshTokenExpiresAt" timestamptz,
  "scope" text,
  "password" text,
  "createdAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" timestamptz NOT NULL,
  CONSTRAINT "fk_account_user_id" FOREIGN KEY ("userId") REFERENCES "users" ("id") ON DELETE CASCADE
);

CREATE TABLE "verification" (
  "id" text NOT NULL PRIMARY KEY,
  "identifier" text NOT NULL,
  "value" text NOT NULL,
  "expiresAt" timestamptz NOT NULL,
  "createdAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "userId" text,
  "callbackUrl" text
);

CREATE TABLE "rateLimit" (
  "id" text NOT NULL PRIMARY KEY,
  "key" text NOT NULL,
  "count" bigint NOT NULL,
  "lastRequest" bigint NOT NULL
);

CREATE TABLE "note" (
  "id" text NOT NULL PRIMARY KEY,
  "createdAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "pinned" boolean DEFAULT false,
  "title" text NOT NULL,
  "userId" text NOT NULL,
  CONSTRAINT "fk_note_user_id" FOREIGN KEY ("userId") REFERENCES "users" ("id") ON DELETE CASCADE
);

CREATE UNIQUE INDEX "idx_users_email" ON "users" ("email");

CREATE UNIQUE INDEX "idx_users_phone_number" ON "users" ("phoneNumber");

CREATE UNIQUE INDEX "idx_users_username" ON "users" ("username");

CREATE INDEX "idx_users_deleted_at" ON "users" ("deletedAt");

CREATE UNIQUE INDEX "idx_session_token" ON "session" ("token");

CREATE INDEX "idx_session_user_id" ON "session" ("userId");

CREATE INDEX "idx_account_user_id" ON "account" ("userId");

CREATE UNIQUE INDEX "idx_provider_account" ON "account" ("providerId", "accountId");

CREATE INDEX "idx_verification_identifier" ON "verification" ("identifier");

CREATE UNIQUE INDEX "idx_rateLimit_key" ON "rateLimit" ("key");

CREATE UNIQUE INDEX "idx_note_user_id_title" ON "note" ("userId", "title");
