-- goauth schema, sqlite, desired state. Generated from goauth's schema registry (core models,
-- additionalFields and plugin schemas); regenerate instead of editing.

CREATE TABLE "users" (
  "id" integer PRIMARY KEY AUTOINCREMENT,
  "name" text NOT NULL,
  "email" text NOT NULL,
  "emailVerified" integer NOT NULL DEFAULT 0,
  "image" text,
  "createdAt" datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "role" text,
  "banned" integer DEFAULT 0,
  "banReason" text,
  "banExpires" datetime,
  "phoneNumber" text,
  "phoneNumberVerified" integer,
  "twoFactorEnabled" integer DEFAULT 0,
  "username" text,
  "displayUsername" text,
  "isAnonymous" integer DEFAULT 0,
  "firstName" text,
  "lastName" text,
  "displayName" text,
  "bio" text,
  "dateOfBirth" datetime,
  "gender" text,
  "locale" text DEFAULT 'en',
  "timezone" text,
  "lastLoginIP" text,
  "lastLoginAt" datetime,
  "lastSeen" datetime,
  "deletedAt" datetime,
  "loyaltyTier" text NOT NULL DEFAULT 'bronze',
  "score" real,
  "tags" text
);

CREATE TABLE "session" (
  "id" integer PRIMARY KEY AUTOINCREMENT,
  "expiresAt" datetime NOT NULL,
  "token" text NOT NULL,
  "createdAt" datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" datetime NOT NULL,
  "ipAddress" text,
  "userAgent" text,
  "userId" integer NOT NULL,
  "impersonatedBy" text,
  "activeOrganizationId" text,
  "activeTeamId" text,
  "activeOrganizationType" text,
  "activeOrganizationRole" text,
  "deviceToken" text,
  "deviceId" text,
  "deviceName" text,
  "deviceType" text,
  "lastUsedAt" datetime,
  CONSTRAINT "fk_session_user_id" FOREIGN KEY ("userId") REFERENCES "users" ("id") ON DELETE CASCADE
);

CREATE TABLE "account" (
  "id" integer PRIMARY KEY AUTOINCREMENT,
  "accountId" text NOT NULL,
  "providerId" text NOT NULL,
  "userId" integer NOT NULL,
  "accessToken" text,
  "refreshToken" text,
  "idToken" text,
  "accessTokenExpiresAt" datetime,
  "refreshTokenExpiresAt" datetime,
  "scope" text,
  "password" text,
  "createdAt" datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" datetime NOT NULL,
  CONSTRAINT "fk_account_user_id" FOREIGN KEY ("userId") REFERENCES "users" ("id") ON DELETE CASCADE
);

CREATE TABLE "verification" (
  "id" integer PRIMARY KEY AUTOINCREMENT,
  "identifier" text NOT NULL,
  "value" text NOT NULL,
  "expiresAt" datetime NOT NULL,
  "createdAt" datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updatedAt" datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "userId" text,
  "callbackUrl" text
);

CREATE TABLE "rateLimit" (
  "id" integer PRIMARY KEY AUTOINCREMENT,
  "key" text NOT NULL,
  "count" integer NOT NULL,
  "lastRequest" integer NOT NULL
);

CREATE TABLE "note" (
  "id" integer PRIMARY KEY AUTOINCREMENT,
  "createdAt" datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "pinned" integer DEFAULT 0,
  "title" text NOT NULL,
  "userId" integer NOT NULL,
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
