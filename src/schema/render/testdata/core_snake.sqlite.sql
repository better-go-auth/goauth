-- goauth schema, sqlite, desired state. Generated from goauth's schema registry (core models,
-- additionalFields and plugin schemas); regenerate instead of editing.

CREATE TABLE "user" (
  "id" text NOT NULL PRIMARY KEY,
  "name" text NOT NULL,
  "email" text NOT NULL,
  "email_verified" integer NOT NULL DEFAULT 0,
  "image" text,
  "created_at" datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "role" text,
  "banned" integer DEFAULT 0,
  "ban_reason" text,
  "ban_expires" datetime,
  "phone_number" text,
  "phone_number_verified" integer,
  "two_factor_enabled" integer DEFAULT 0,
  "username" text,
  "display_username" text,
  "is_anonymous" integer DEFAULT 0,
  "first_name" text,
  "last_name" text,
  "display_name" text,
  "bio" text,
  "date_of_birth" datetime,
  "gender" text,
  "locale" text DEFAULT 'en',
  "timezone" text,
  "last_login_ip" text,
  "last_login_at" datetime,
  "last_seen" datetime,
  "deleted_at" datetime
);

CREATE TABLE "session" (
  "id" text NOT NULL PRIMARY KEY,
  "expires_at" datetime NOT NULL,
  "token" text NOT NULL,
  "created_at" datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" datetime NOT NULL,
  "ip_address" text,
  "user_agent" text,
  "user_id" text NOT NULL,
  "impersonated_by" text,
  "active_organization_id" text,
  "active_team_id" text,
  "active_organization_type" text,
  "active_organization_role" text,
  "device_token" text,
  "device_id" text,
  "device_name" text,
  "device_type" text,
  "last_used_at" datetime,
  CONSTRAINT "fk_session_user_id" FOREIGN KEY ("user_id") REFERENCES "user" ("id") ON DELETE CASCADE
);

CREATE TABLE "account" (
  "id" text NOT NULL PRIMARY KEY,
  "account_id" text NOT NULL,
  "provider_id" text NOT NULL,
  "user_id" text NOT NULL,
  "access_token" text,
  "refresh_token" text,
  "id_token" text,
  "access_token_expires_at" datetime,
  "refresh_token_expires_at" datetime,
  "scope" text,
  "password" text,
  "created_at" datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" datetime NOT NULL,
  CONSTRAINT "fk_account_user_id" FOREIGN KEY ("user_id") REFERENCES "user" ("id") ON DELETE CASCADE
);

CREATE TABLE "verification" (
  "id" text NOT NULL PRIMARY KEY,
  "identifier" text NOT NULL,
  "value" text NOT NULL,
  "expires_at" datetime NOT NULL,
  "created_at" datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" datetime NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "user_id" text,
  "callback_url" text
);

CREATE UNIQUE INDEX "idx_user_email" ON "user" ("email");

CREATE UNIQUE INDEX "idx_user_phone_number" ON "user" ("phone_number");

CREATE UNIQUE INDEX "idx_user_username" ON "user" ("username");

CREATE INDEX "idx_user_deleted_at" ON "user" ("deleted_at");

CREATE UNIQUE INDEX "idx_session_token" ON "session" ("token");

CREATE INDEX "idx_session_user_id" ON "session" ("user_id");

CREATE INDEX "idx_account_user_id" ON "account" ("user_id");

CREATE UNIQUE INDEX "idx_provider_account" ON "account" ("provider_id", "account_id");

CREATE INDEX "idx_verification_identifier" ON "verification" ("identifier");
