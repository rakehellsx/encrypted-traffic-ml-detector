CREATE TABLE `apiKeys` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`name` varchar(80) NOT NULL,
	`keyPrefix` varchar(16) NOT NULL,
	`keyHash` varchar(64) NOT NULL,
	`isActive` boolean NOT NULL DEFAULT true,
	`lastUsedAt` timestamp,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `apiKeys_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
ALTER TABLE `datasets` ADD `trafficClass` varchar(32) DEFAULT 'unlabeled' NOT NULL;--> statement-breakpoint
ALTER TABLE `detectionFlows` ADD `predictedClass` varchar(32) DEFAULT 'unlabeled' NOT NULL;--> statement-breakpoint
ALTER TABLE `detectionFlows` ADD `classScoresJson` text NOT NULL;--> statement-breakpoint
ALTER TABLE `modelVersions` ADD `classSetJson` text NOT NULL;--> statement-breakpoint
ALTER TABLE `trainingJobs` ADD `classSetJson` text NOT NULL;--> statement-breakpoint
ALTER TABLE `uploadTasks` ADD `trafficClass` varchar(32) DEFAULT 'unlabeled' NOT NULL;