ALTER TABLE `modelVersions` MODIFY COLUMN `algorithm` enum('logistic_regression','gaussian_nb','lightgbm_kitnet','abonnen_random_forest','abonnen_gbdt') NOT NULL;--> statement-breakpoint
ALTER TABLE `trainingJobs` MODIFY COLUMN `algorithm` enum('logistic_regression','gaussian_nb','lightgbm_kitnet','abonnen_random_forest','abonnen_gbdt') NOT NULL;--> statement-breakpoint
ALTER TABLE `flowFeatures` ADD `abonnenJson` text;--> statement-breakpoint
ALTER TABLE `flowFeatures` ADD `abonnenSource` varchar(32) DEFAULT 'native_compatibility' NOT NULL;
