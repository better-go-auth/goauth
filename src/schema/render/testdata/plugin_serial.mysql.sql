-- goauth schema, mysql, desired state. Generated from goauth's schema registry (core models,
-- additionalFields and plugin schemas); regenerate instead of editing.

CREATE TABLE `users` (
  `id` bigint NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `name` varchar(255) NOT NULL,
  `email` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `emailVerified` boolean NOT NULL DEFAULT false,
  `image` text,
  `createdAt` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updatedAt` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `role` text,
  `banned` boolean DEFAULT false,
  `banReason` text,
  `banExpires` datetime(3),
  `phoneNumber` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
  `phoneNumberVerified` boolean,
  `twoFactorEnabled` boolean DEFAULT false,
  `username` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin,
  `displayUsername` text,
  `isAnonymous` boolean DEFAULT false,
  `firstName` text,
  `lastName` text,
  `displayName` text,
  `bio` text,
  `dateOfBirth` datetime(3),
  `gender` text,
  `locale` varchar(255) DEFAULT 'en',
  `timezone` text,
  `lastLoginIP` text,
  `lastLoginAt` datetime(3),
  `lastSeen` datetime(3),
  `deletedAt` datetime(3),
  `loyaltyTier` varchar(255) NOT NULL DEFAULT 'bronze',
  `score` double,
  `tags` json
);

CREATE TABLE `session` (
  `id` bigint NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `expiresAt` datetime(3) NOT NULL,
  `token` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `createdAt` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updatedAt` datetime(3) NOT NULL,
  `ipAddress` text,
  `userAgent` text,
  `userId` bigint NOT NULL,
  `impersonatedBy` text,
  `activeOrganizationId` text,
  `activeTeamId` text,
  `activeOrganizationType` text,
  `activeOrganizationRole` text,
  `deviceToken` text,
  `deviceId` text,
  `deviceName` text,
  `deviceType` text,
  `lastUsedAt` datetime(3),
  CONSTRAINT `fk_session_user_id` FOREIGN KEY (`userId`) REFERENCES `users` (`id`) ON DELETE CASCADE
);

CREATE TABLE `account` (
  `id` bigint NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `accountId` varchar(255) NOT NULL,
  `providerId` varchar(255) NOT NULL,
  `userId` bigint NOT NULL,
  `accessToken` text,
  `refreshToken` text,
  `idToken` text,
  `accessTokenExpiresAt` datetime(3),
  `refreshTokenExpiresAt` datetime(3),
  `scope` text,
  `password` text,
  `createdAt` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updatedAt` datetime(3) NOT NULL,
  CONSTRAINT `fk_account_user_id` FOREIGN KEY (`userId`) REFERENCES `users` (`id`) ON DELETE CASCADE
);

CREATE TABLE `verification` (
  `id` bigint NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `identifier` varchar(255) NOT NULL,
  `value` text NOT NULL,
  `expiresAt` datetime(3) NOT NULL,
  `createdAt` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `updatedAt` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `userId` varchar(255),
  `callbackUrl` text
);

CREATE TABLE `rateLimit` (
  `id` bigint NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `key` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_bin NOT NULL,
  `count` bigint NOT NULL,
  `lastRequest` bigint NOT NULL
);

CREATE TABLE `note` (
  `id` bigint NOT NULL AUTO_INCREMENT PRIMARY KEY,
  `createdAt` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `pinned` boolean DEFAULT false,
  `title` varchar(255) NOT NULL,
  `userId` bigint NOT NULL,
  CONSTRAINT `fk_note_user_id` FOREIGN KEY (`userId`) REFERENCES `users` (`id`) ON DELETE CASCADE
);

CREATE UNIQUE INDEX `idx_users_email` ON `users` (`email`);

CREATE UNIQUE INDEX `idx_users_phone_number` ON `users` (`phoneNumber`);

CREATE UNIQUE INDEX `idx_users_username` ON `users` (`username`);

CREATE INDEX `idx_users_deleted_at` ON `users` (`deletedAt`);

CREATE UNIQUE INDEX `idx_session_token` ON `session` (`token`);

CREATE INDEX `idx_session_user_id` ON `session` (`userId`);

CREATE INDEX `idx_account_user_id` ON `account` (`userId`);

CREATE UNIQUE INDEX `idx_provider_account` ON `account` (`providerId`, `accountId`);

CREATE INDEX `idx_verification_identifier` ON `verification` (`identifier`);

CREATE UNIQUE INDEX `idx_rateLimit_key` ON `rateLimit` (`key`);

CREATE UNIQUE INDEX `idx_note_user_id_title` ON `note` (`userId`, `title`);
