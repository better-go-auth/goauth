# goauth schema, sqlite, Atlas HCL. Generated from goauth's schema registry (core models,
# additionalFields and plugin schemas); regenerate instead of editing.

schema "main" {
}

table "users" {
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
  column "emailVerified" {
    null    = false
    type    = integer
    default = 0
  }
  column "image" {
    null = true
    type = text
  }
  column "createdAt" {
    null    = false
    type    = datetime
    default = sql("CURRENT_TIMESTAMP")
  }
  column "updatedAt" {
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
  column "banReason" {
    null = true
    type = text
  }
  column "banExpires" {
    null = true
    type = datetime
  }
  column "phoneNumber" {
    null = true
    type = text
  }
  column "phoneNumberVerified" {
    null = true
    type = integer
  }
  column "twoFactorEnabled" {
    null    = true
    type    = integer
    default = 0
  }
  column "username" {
    null = true
    type = text
  }
  column "displayUsername" {
    null = true
    type = text
  }
  column "isAnonymous" {
    null    = true
    type    = integer
    default = 0
  }
  column "firstName" {
    null = true
    type = text
  }
  column "lastName" {
    null = true
    type = text
  }
  column "displayName" {
    null = true
    type = text
  }
  column "bio" {
    null = true
    type = text
  }
  column "dateOfBirth" {
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
  column "lastLoginIP" {
    null = true
    type = text
  }
  column "lastLoginAt" {
    null = true
    type = datetime
  }
  column "lastSeen" {
    null = true
    type = datetime
  }
  column "deletedAt" {
    null = true
    type = datetime
  }
  column "loyaltyTier" {
    null    = false
    type    = text
    default = "bronze"
  }
  column "score" {
    null = true
    type = real
  }
  column "tags" {
    null = true
    type = text
  }
  primary_key {
    columns = [column.id]
  }
  index "idx_users_email" {
    unique  = true
    columns = [column.email]
  }
  index "idx_users_phone_number" {
    unique  = true
    columns = [column.phoneNumber]
  }
  index "idx_users_username" {
    unique  = true
    columns = [column.username]
  }
  index "idx_users_deleted_at" {
    columns = [column.deletedAt]
  }
}

table "session" {
  schema = schema.main
  column "id" {
    null = false
    type = text
  }
  column "expiresAt" {
    null = false
    type = datetime
  }
  column "token" {
    null = false
    type = text
  }
  column "createdAt" {
    null    = false
    type    = datetime
    default = sql("CURRENT_TIMESTAMP")
  }
  column "updatedAt" {
    null = false
    type = datetime
  }
  column "ipAddress" {
    null = true
    type = text
  }
  column "userAgent" {
    null = true
    type = text
  }
  column "userId" {
    null = false
    type = text
  }
  column "impersonatedBy" {
    null = true
    type = text
  }
  column "activeOrganizationId" {
    null = true
    type = text
  }
  column "activeTeamId" {
    null = true
    type = text
  }
  column "activeOrganizationType" {
    null = true
    type = text
  }
  column "activeOrganizationRole" {
    null = true
    type = text
  }
  column "deviceToken" {
    null = true
    type = text
  }
  column "deviceId" {
    null = true
    type = text
  }
  column "deviceName" {
    null = true
    type = text
  }
  column "deviceType" {
    null = true
    type = text
  }
  column "lastUsedAt" {
    null = true
    type = datetime
  }
  primary_key {
    columns = [column.id]
  }
  foreign_key "fk_session_user_id" {
    columns     = [column.userId]
    ref_columns = [table.users.column.id]
    on_update   = NO_ACTION
    on_delete   = CASCADE
  }
  index "idx_session_token" {
    unique  = true
    columns = [column.token]
  }
  index "idx_session_user_id" {
    columns = [column.userId]
  }
}

table "account" {
  schema = schema.main
  column "id" {
    null = false
    type = text
  }
  column "accountId" {
    null = false
    type = text
  }
  column "providerId" {
    null = false
    type = text
  }
  column "userId" {
    null = false
    type = text
  }
  column "accessToken" {
    null = true
    type = text
  }
  column "refreshToken" {
    null = true
    type = text
  }
  column "idToken" {
    null = true
    type = text
  }
  column "accessTokenExpiresAt" {
    null = true
    type = datetime
  }
  column "refreshTokenExpiresAt" {
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
  column "createdAt" {
    null    = false
    type    = datetime
    default = sql("CURRENT_TIMESTAMP")
  }
  column "updatedAt" {
    null = false
    type = datetime
  }
  primary_key {
    columns = [column.id]
  }
  foreign_key "fk_account_user_id" {
    columns     = [column.userId]
    ref_columns = [table.users.column.id]
    on_update   = NO_ACTION
    on_delete   = CASCADE
  }
  index "idx_account_user_id" {
    columns = [column.userId]
  }
  index "idx_provider_account" {
    unique  = true
    columns = [column.providerId, column.accountId]
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
  column "expiresAt" {
    null = false
    type = datetime
  }
  column "createdAt" {
    null    = false
    type    = datetime
    default = sql("CURRENT_TIMESTAMP")
  }
  column "updatedAt" {
    null    = false
    type    = datetime
    default = sql("CURRENT_TIMESTAMP")
  }
  column "userId" {
    null = true
    type = text
  }
  column "callbackUrl" {
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

table "rateLimit" {
  schema = schema.main
  column "id" {
    null = false
    type = text
  }
  column "key" {
    null = false
    type = text
  }
  column "count" {
    null = false
    type = integer
  }
  column "lastRequest" {
    null = false
    type = integer
  }
  primary_key {
    columns = [column.id]
  }
  index "idx_rateLimit_key" {
    unique  = true
    columns = [column.key]
  }
}

table "note" {
  schema = schema.main
  column "id" {
    null = false
    type = text
  }
  column "createdAt" {
    null    = false
    type    = datetime
    default = sql("CURRENT_TIMESTAMP")
  }
  column "pinned" {
    null    = true
    type    = integer
    default = 0
  }
  column "title" {
    null = false
    type = text
  }
  column "userId" {
    null = false
    type = text
  }
  primary_key {
    columns = [column.id]
  }
  foreign_key "fk_note_user_id" {
    columns     = [column.userId]
    ref_columns = [table.users.column.id]
    on_update   = NO_ACTION
    on_delete   = CASCADE
  }
  index "idx_note_user_id_title" {
    unique  = true
    columns = [column.userId, column.title]
  }
}
