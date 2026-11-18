-- goauth schema, mysql, additive migration. Generated from goauth's schema registry (core models,
-- additionalFields and plugin schemas); regenerate instead of editing.

CREATE TABLE `note` (
  `id` varchar(255) NOT NULL PRIMARY KEY,
  `createdAt` datetime(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `pinned` boolean DEFAULT false,
  `title` varchar(255) NOT NULL,
  `userId` varchar(255) NOT NULL,
  CONSTRAINT `fk_note_user_id` FOREIGN KEY (`userId`) REFERENCES `users` (`id`) ON DELETE CASCADE
);

ALTER TABLE `users` ADD COLUMN `loyaltyTier` varchar(255) NOT NULL DEFAULT 'bronze';

ALTER TABLE `users` ADD COLUMN `score` double;

CREATE UNIQUE INDEX `idx_users_email` ON `users` (`email`);

CREATE UNIQUE INDEX `idx_note_user_id_title` ON `note` (`userId`, `title`);
