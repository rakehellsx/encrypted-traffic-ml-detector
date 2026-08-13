CREATE TABLE `annotationSets` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`name` varchar(96) NOT NULL,
	`description` varchar(255),
	`labelsJson` text NOT NULL,
	`isActive` boolean NOT NULL DEFAULT true,
	`isDefault` boolean NOT NULL DEFAULT false,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `annotationSets_id` PRIMARY KEY(`id`),
	CONSTRAINT `annotation_sets_user_name_idx` UNIQUE(`userId`,`name`)
);
--> statement-breakpoint
ALTER TABLE `datasets` ADD `annotationSetId` int;--> statement-breakpoint
ALTER TABLE `datasets` ADD `annotationSnapshotJson` text;--> statement-breakpoint
ALTER TABLE `detectionTasks` ADD `annotationSetId` int;--> statement-breakpoint
ALTER TABLE `detectionTasks` ADD `annotationSnapshotJson` text;--> statement-breakpoint
ALTER TABLE `modelVersions` ADD `annotationSetId` int;--> statement-breakpoint
ALTER TABLE `modelVersions` ADD `annotationSnapshotJson` text;--> statement-breakpoint
ALTER TABLE `trainingJobs` ADD `annotationSetId` int;--> statement-breakpoint
ALTER TABLE `trainingJobs` ADD `annotationSnapshotJson` text;--> statement-breakpoint
ALTER TABLE `uploadTasks` ADD `annotationSetId` int;--> statement-breakpoint
ALTER TABLE `uploadTasks` ADD `annotationSnapshotJson` text;