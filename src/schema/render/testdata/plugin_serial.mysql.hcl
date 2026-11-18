# goauth schema, mysql, Atlas HCL. Generated from goauth's schema registry (core models,
# additionalFields and plugin schemas); regenerate instead of editing.

schema "goauth" {
}

table "users" {
  schema = schema.goauth
  column "id" {
    null           = false
    type           = bigint
    auto_increment = true
  }
  column "name" {
    null = false
    type = varchar(255)
  }
  column "email" {
    null    = false
    type    = varchar(255)
    charset = "utf8mb4"
    collate = "utf8mb4_bin"
  }
  column "emailVerified" {
    null    = false
    type    = bool
    default = false
  }
  column "image" {
    null = true
    type = text
  }
  column "createdAt" {
    null    = false
    type    = datetime(3)
    default = sql("CURRENT_TIMESTAMP(3)")
  }
  column "updatedAt" {
    null    = false
    type    = datetime(3)
    default = sql("CURRENT_TIMESTAMP(3)")
  }
  column "role" {
    null = true
    type = text
  }
  column "banned" {
    null    = true
    type    = bool
    default = false
  }
  column "banReason" {
    null = true
    type = text
  }
  column "banExpires" {
    null = true
    type = datetime(3)
  }
  column "phoneNumber" {
    null    = true
    type    = varchar(255)
    charset = "utf8mb4"
    collate = "utf8mb4_bin"
  }
  column "phoneNumberVerified" {
    null = true
    type = bool
  }
  column "twoFactorEnabled" {
    null    = true
    type    = bool
    default = false
  }
  column "username" {
    null    = true
    type    = varchar(255)
    charset = "utf8mb4"
    collate = "utf8mb4_bin"
  }
  column "displayUsername" {
    null = true
    type = text
  }
  column "isAnonymous" {
    null    = true
    type    = bool
    default = false
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
    type = datetime(3)
  }
  column "gender" {
    null = true
    type = text
  }
  column "locale" {
    null    = true
    type    = varchar(255)
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
    type = datetime(3)
  }
  column "lastSeen" {
    null = true
    type = datetime(3)
  }
  column "deletedAt" {
    null = true
    type = datetime(3)
  }
  column "loyaltyTier" {
    null    = false
    type    = varchar(255)
    default = "bronze"
  }
  column "score" {
    null = true
    type = double
  }
  column "tags" {
    null = true
    type = json
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
  schema = schema.goauth
  column "id" {
    null           = false
    type           = bigint
    auto_increment = true
  }
  column "expiresAt" {
    null = false
    type = datetime(3)
  }
  column "token" {
    null    = false
    type    = varchar(255)
    charset = "utf8mb4"
    collate = "utf8mb4_bin"
  }
  column "createdAt" {
    null    = false
    type    = datetime(3)
    default = sql("CURRENT_TIMESTAMP(3)")
  }
  column "updatedAt" {
    null = false
    type = datetime(3)
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
    type = bigint
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
    type = datetime(3)
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
  schema = schema.goauth
  column "id" {
    null           = false
    type           = bigint
    auto_increment = true
  }
  column "accountId" {
    null = false
    type = varchar(255)
  }
  column "providerId" {
    null = false
    type = varchar(255)
  }
  column "userId" {
    null = false
    type = bigint
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
    type = datetime(3)
  }
  column "refreshTokenExpiresAt" {
    null = true
    type = datetime(3)
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
    type    = datetime(3)
    default = sql("CURRENT_TIMESTAMP(3)")
  }
  column "updatedAt" {
    null = false
    type = datetime(3)
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
  schema = schema.goauth
  column "id" {
    null           = false
    type           = bigint
    auto_increment = true
  }
  column "identifier" {
    null = false
    type = varchar(255)
  }
  column "value" {
    null = false
    type = text
  }
  column "expiresAt" {
    null = false
    type = datetime(3)
  }
  column "createdAt" {
    null    = false
    type    = datetime(3)
    default = sql("CURRENT_TIMESTAMP(3)")
  }
  column "updatedAt" {
    null    = false
    type    = datetime(3)
    default = sql("CURRENT_TIMESTAMP(3)")
  }
  column "userId" {
    null = true
    type = varchar(255)
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
  schema = schema.goauth
  column "id" {
    null           = false
    type           = bigint
    auto_increment = true
  }
  column "key" {
    null    = false
    type    = varchar(255)
    charset = "utf8mb4"
    collate = "utf8mb4_bin"
  }
  column "count" {
    null = false
    type = bigint
  }
  column "lastRequest" {
    null = false
    type = bigint
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
  schema = schema.goauth
  column "id" {
    null           = false
    type           = bigint
    auto_increment = true
  }
  column "createdAt" {
    null    = false
    type    = datetime(3)
    default = sql("CURRENT_TIMESTAMP(3)")
  }
  column "pinned" {
    null    = true
    type    = bool
    default = false
  }
  column "title" {
    null = false
    type = varchar(255)
  }
  column "userId" {
    null = false
    type = bigint
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
