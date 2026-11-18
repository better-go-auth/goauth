-- goauth schema, postgres, desired state. Generated from goauth's schema registry (core models,
-- additionalFields and plugin schemas); regenerate instead of editing.

CREATE TABLE "user" (
  "id" text NOT NULL PRIMARY KEY,
  "name" text NOT NULL,
  "email" text NOT NULL,
  "email_verified" boolean NOT NULL DEFAULT false,
  "image" text,
  "created_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "role" text,
  "banned" boolean DEFAULT false,
  "ban_reason" text,
  "ban_expires" timestamptz,
  "phone_number" text,
  "phone_number_verified" boolean,
  "two_factor_enabled" boolean DEFAULT false,
  "username" text,
  "display_username" text,
  "is_anonymous" boolean DEFAULT false,
  "first_name" text,
  "last_name" text,
  "display_name" text,
  "bio" text,
  "date_of_birth" timestamptz,
  "gender" text,
  "locale" text DEFAULT 'en',
  "timezone" text,
  "last_login_ip" text,
  "last_login_at" timestamptz,
  "last_seen" timestamptz,
  "deleted_at" timestamptz
);

CREATE TABLE "session" (
  "id" text NOT NULL PRIMARY KEY,
  "expires_at" timestamptz NOT NULL,
  "token" text NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" timestamptz NOT NULL,
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
  "last_used_at" timestamptz,
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
  "access_token_expires_at" timestamptz,
  "refresh_token_expires_at" timestamptz,
  "scope" text,
  "password" text,
  "created_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" timestamptz NOT NULL,
  CONSTRAINT "fk_account_user_id" FOREIGN KEY ("user_id") REFERENCES "user" ("id") ON DELETE CASCADE
);

CREATE TABLE "verification" (
  "id" text NOT NULL PRIMARY KEY,
  "identifier" text NOT NULL,
  "value" text NOT NULL,
  "expires_at" timestamptz NOT NULL,
  "created_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
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
