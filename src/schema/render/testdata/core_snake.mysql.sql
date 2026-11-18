-- goauth schema, mysql, desired state. Generated from goauth's schema registry (core models,
-- additionalFields and plugin schemas); regenerate instead of editing.

CREATE TABLE `user` (
  `id` varchar(255) NOT NULL PRIMARY KEY,
  `name` varchar(255) NOT NULL,
  `email` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `email_verified` boolean NOT NULL DEFAULT false,
  `image` text,
  `created_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `role` text,
  `banned` boolean DEFAULT false,
  `ban_reason` text,
  `ban_expires` datetime(3),
  `phone_number` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
  `phone_number_verified` boolean,
  `two_factor_enabled` boolean DEFAULT false,
  `username` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
  `display_username` text,
  `is_anonymous` boolean DEFAULT false,
  `first_name` text,
  `last_name` text,
  `display_name` text,
  `bio` text,
  `date_of_birth` datetime(3),
  `gender` text,
  `locale` varchar(255) DEFAULT 'en',
  `timezone` text,
  `last_login_ip` text,
  `last_login_at` datetime(3),
  `last_seen` datetime(3),
  `deleted_at` datetime(3)
);

CREATE TABLE `session` (
  `id` varchar(255) NOT NULL PRIMARY KEY,
  `expires_at` datetime(3) NOT NULL,
  `token` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `created_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at` datetime(3) NOT NULL,
  `ip_address` text,
  `user_agent` text,
  `user_id` varchar(255) NOT NULL,
  `impersonated_by` text,
  `active_organization_id` text,
  `active_team_id` text,
  `active_organization_type` text,
  `active_organization_role` text,
  `device_token` text,
  `device_id` text,
  `device_name` text,
  `device_type` text,
  `last_used_at` datetime(3),
  CONSTRAINT `fk_session_user_id` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE
);

CREATE TABLE `account` (
  `id` varchar(255) NOT NULL PRIMARY KEY,
  `account_id` varchar(255) NOT NULL,
  `provider_id` varchar(255) NOT NULL,
  `user_id` varchar(255) NOT NULL,
  `access_token` text,
  `refresh_token` text,
  `id_token` text,
  `access_token_expires_at` datetime(3),
  `refresh_token_expires_at` datetime(3),
  `scope` text,
  `password` text,
  `created_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at` datetime(3) NOT NULL,
  CONSTRAINT `fk_account_user_id` FOREIGN KEY (`user_id`) REFERENCES `user` (`id`) ON DELETE CASCADE
);

CREATE TABLE `verification` (
  `id` varchar(255) NOT NULL PRIMARY KEY,
  `identifier` varchar(255) NOT NULL,
  `value` text NOT NULL,
  `expires_at` datetime(3) NOT NULL,
  `created_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updated_at` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `user_id` text,
  `callback_url` text
);

CREATE UNIQUE INDEX `idx_user_email` ON `user` (`email`);

CREATE UNIQUE INDEX `idx_user_phone_number` ON `user` (`phone_number`);

CREATE UNIQUE INDEX `idx_user_username` ON `user` (`username`);

CREATE INDEX `idx_user_deleted_at` ON `user` (`deleted_at`);

CREATE UNIQUE INDEX `idx_session_token` ON `session` (`token`);

CREATE INDEX `idx_session_user_id` ON `session` (`user_id`);

CREATE INDEX `idx_account_user_id` ON `account` (`user_id`);

CREATE UNIQUE INDEX `idx_provider_account` ON `account` (`provider_id`, `account_id`);

CREATE INDEX `idx_verification_identifier` ON `verification` (`identifier`);
