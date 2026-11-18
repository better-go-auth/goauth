-- goauth schema, postgres, additive migration. Generated from goauth's schema registry (core models,
-- additionalFields and plugin schemas); regenerate instead of editing.

CREATE TABLE "note" (
  "id" text NOT NULL PRIMARY KEY,
  "createdAt" timestamptz NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "pinned" boolean DEFAULT false,
  "title" text NOT NULL,
  "userId" text NOT NULL,
  CONSTRAINT "fk_note_user_id" FOREIGN KEY ("userId") REFERENCES "users" ("id") ON DELETE CASCADE
);

ALTER TABLE "users" ADD COLUMN "loyaltyTier" text NOT NULL DEFAULT 'bronze';

ALTER TABLE "users" ADD COLUMN "score" double precision;

CREATE UNIQUE INDEX "idx_users_email" ON "users" ("email");

CREATE UNIQUE INDEX "idx_note_user_id_title" ON "note" ("userId", "title");
