# goauth schema, sqlite, Atlas HCL. Generated from goauth's schema registry (core models,
# additionalFields and plugin schemas); regenerate instead of editing.

schema "main" {
}

table "user" {
  schema = schema.main
  column "id" {
    null = false
    type = text
  }
  column "name" {
    null = false
    type = text
  }
  column "email" {
    null = false
    type = text
  }
  column "email_verified" {
    null    = false
    type    = integer
    default = 0
  }
  column "image" {
    null = true
    type = text
  }
  column "created_at" {
    null    = false
    type    = datetime
    default = sql("CURRENT_TIMESTAMP")
  }
  column "updated_at" {
    null    = false
    type    = datetime
    default = sql("CURRENT_TIMESTAMP")
  }
  column "role" {
    null = true
    type = text
  }
  column "banned" {
    null    = true
    type    = integer
    default = 0
  }
  column "ban_reason" {
    null = true
    type = text
  }
  column "ban_expires" {
    null = true
    type = datetime
  }
  column "phone_number" {
    null = true
    type = text
  }
  column "phone_number_verified" {
    null = true
    type = integer
  }
  column "two_factor_enabled" {
    null    = true
    type    = integer
    default = 0
  }
  column "username" {
    null = true
    type = text
  }
  column "display_username" {
    null = true
    type = text
  }
  column "is_anonymous" {
    null    = true
    type    = integer
    default = 0
  }
  column "first_name" {
    null = true
    type = text
  }
  column "last_name" {
    null = true
    type = text
  }
  column "display_name" {
    null = true
    type = text
  }
  column "bio" {
    null = true
    type = text
  }
  column "date_of_birth" {
    null = true
    type = datetime
  }
  column "gender" {
    null = true
    type = text
  }
  column "locale" {
    null    = true
    type    = text
    default = "en"
  }
  column "timezone" {
    null = true
    type = text
  }
  column "last_login_ip" {
    null = true
    type = text
  }
  column "last_login_at" {
    null = true
    type = datetime
  }
  column "last_seen" {
    null = true
    type = datetime
  }
  column "deleted_at" {
    null = true
    type = datetime
  }
  primary_key {
    columns = [column.id]
  }
  index "idx_user_email" {
    unique  = true
    columns = [column.email]
  }
  index "idx_user_phone_number" {
    unique  = true
    columns = [column.phone_number]
  }
  index "idx_user_username" {
    unique  = true
    columns = [column.username]
  }
  index "idx_user_deleted_at" {
    columns = [column.deleted_at]
  }
}

table "session" {
  schema = schema.main
  column "id" {
    null = false
    type = text
  }
  column "expires_at" {
    null = false
    type = datetime
  }
  column "token" {
    null = false
    type = text
  }
  column "created_at" {
    null    = false
    type    = datetime
    default = sql("CURRENT_TIMESTAMP")
  }
  column "updated_at" {
    null = false
    type = datetime
  }
  column "ip_address" {
    null = true
    type = text
  }
  column "user_agent" {
    null = true
    type = text
  }
  column "user_id" {
    null = false
    type = text
  }
  column "impersonated_by" {
    null = true
    type = text
  }
  column "active_organization_id" {
    null = true
    type = text
  }
  column "active_team_id" {
    null = true
    type = text
  }
  column "active_organization_type" {
    null = true
    type = text
  }
  column "active_organization_role" {
    null = true
    type = text
  }
  column "device_token" {
    null = true
    type = text
  }
  column "device_id" {
    null = true
    type = text
  }
  column "device_name" {
    null = true
    type = text
  }
  column "device_type" {
    null = true
    type = text
  }
  column "last_used_at" {
    null = true
    type = datetime
  }
  primary_key {
    columns = [column.id]
  }
  foreign_key "fk_session_user_id" {
    columns     = [column.user_id]
    ref_columns = [table.user.column.id]
    on_update   = NO_ACTION
    on_delete   = CASCADE
  }
  index "idx_session_token" {
    unique  = true
    columns = [column.token]
  }
  index "idx_session_user_id" {
    columns = [column.user_id]
  }
}

table "account" {
  schema = schema.main
  column "id" {
    null = false
    type = text
  }
  column "account_id" {
    null = false
    type = text
  }
  column "provider_id" {
    null = false
    type = text
  }
  column "user_id" {
    null = false
    type = text
  }
  column "access_token" {
    null = true
    type = text
  }
  column "refresh_token" {
    null = true
    type = text
  }
  column "id_token" {
    null = true
    type = text
  }
  column "access_token_expires_at" {
    null = true
    type = datetime
  }
  column "refresh_token_expires_at" {
    null = true
    type = datetime
  }
  column "scope" {
    null = true
    type = text
  }
  column "password" {
    null = true
    type = text
  }
  column "created_at" {
    null    = false
    type    = datetime
    default = sql("CURRENT_TIMESTAMP")
  }
  column "updated_at" {
    null = false
    type = datetime
  }
  primary_key {
    columns = [column.id]
  }
  foreign_key "fk_account_user_id" {
    columns     = [column.user_id]
    ref_columns = [table.user.column.id]
    on_update   = NO_ACTION
    on_delete   = CASCADE
  }
  index "idx_account_user_id" {
    columns = [column.user_id]
  }
  index "idx_provider_account" {
    unique  = true
    columns = [column.provider_id, column.account_id]
  }
}

table "verification" {
  schema = schema.main
  column "id" {
    null = false
    type = text
  }
  column "identifier" {
    null = false
    type = text
  }
  column "value" {
    null = false
    type = text
  }
  column "expires_at" {
    null = false
    type = datetime
  }
  column "created_at" {
    null    = false
    type    = datetime
    default = sql("CURRENT_TIMESTAMP")
  }
  column "updated_at" {
    null    = false
    type    = datetime
    default = sql("CURRENT_TIMESTAMP")
  }
  column "user_id" {
    null = true
    type = text
  }
  column "callback_url" {
    null = true
    type = text
  }
  primary_key {
    columns = [column.id]
  }
  index "idx_verification_identifier" {
    columns = [column.identifier]
  }
}
