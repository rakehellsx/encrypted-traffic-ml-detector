CREATE TABLE `datasets` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`name` varchar(255) NOT NULL,
	`storageKey` varchar(512) NOT NULL,
	`fileSize` int NOT NULL,
	`packetCount` int NOT NULL DEFAULT 0,
	`flowCount` int NOT NULL DEFAULT 0,
	`protocolJson` text NOT NULL,
	`label` enum('benign','malicious','unlabeled') NOT NULL DEFAULT 'unlabeled',
	`extractionStatus` enum('ready','failed') NOT NULL DEFAULT 'ready',
	`errorMessage` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `datasets_id` PRIMARY KEY(`id`),
	CONSTRAINT `datasets_user_name_idx` UNIQUE(`userId`,`name`)
);
--> statement-breakpoint
CREATE TABLE `detectionFlows` (
	`id` int AUTO_INCREMENT NOT NULL,
	`taskId` int NOT NULL,
	`flowKey` varchar(512) NOT NULL,
	`sourceIp` varchar(64) NOT NULL,
	`sourcePort` int NOT NULL,
	`destinationIp` varchar(64) NOT NULL,
	`destinationPort` int NOT NULL,
	`transportProtocol` varchar(16) NOT NULL,
	`riskScore` double NOT NULL,
	`reasonsJson` text NOT NULL,
	`featureJson` text NOT NULL,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `detectionFlows_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `detectionTasks` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`modelVersionId` int NOT NULL,
	`fileName` varchar(255) NOT NULL,
	`storageKey` varchar(512) NOT NULL,
	`status` enum('completed','failed') NOT NULL DEFAULT 'completed',
	`totalFlows` int NOT NULL DEFAULT 0,
	`highRiskFlows` int NOT NULL DEFAULT 0,
	`averageRisk` double NOT NULL DEFAULT 0,
	`summaryJson` text NOT NULL,
	`errorMessage` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `detectionTasks_id` PRIMARY KEY(`id`)
);
--> statement-breakpoint
CREATE TABLE `flowFeatures` (
	`id` int AUTO_INCREMENT NOT NULL,
	`datasetId` int NOT NULL,
	`flowKey` varchar(512) NOT NULL,
	`sourceIp` varchar(64) NOT NULL,
	`sourcePort` int NOT NULL,
	`destinationIp` varchar(64) NOT NULL,
	`destinationPort` int NOT NULL,
	`transportProtocol` varchar(16) NOT NULL,
	`applicationProtocol` varchar(32) NOT NULL DEFAULT 'UNKNOWN',
	`packetCount` int NOT NULL,
	`byteCount` int NOT NULL,
	`upPackets` int NOT NULL,
	`downPackets` int NOT NULL,
	`upBytes` int NOT NULL,
	`downBytes` int NOT NULL,
	`durationMs` double NOT NULL,
	`avgPacketLength` double NOT NULL,
	`stdPacketLength` double NOT NULL,
	`avgIatMs` double NOT NULL,
	`stdIatMs` double NOT NULL,
	`uplinkRatio` double NOT NULL,
	`spltJson` text NOT NULL,
	`tlsVersion` varchar(32) NOT NULL DEFAULT 'UNKNOWN',
	`ja3` varchar(64),
	`sniVisibility` enum('visible','not_observed') NOT NULL DEFAULT 'not_observed',
	`sni` varchar(255),
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `flowFeatures_id` PRIMARY KEY(`id`),
	CONSTRAINT `flow_features_dataset_key_idx` UNIQUE(`datasetId`,`flowKey`)
);
--> statement-breakpoint
CREATE TABLE `modelVersions` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`versionName` varchar(64) NOT NULL,
	`algorithm` enum('logistic_regression','gaussian_nb') NOT NULL,
	`featureSetJson` text NOT NULL,
	`metricsJson` text NOT NULL,
	`modelJson` text NOT NULL,
	`trainedDatasetIdsJson` text NOT NULL,
	`isActive` boolean NOT NULL DEFAULT false,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	CONSTRAINT `modelVersions_id` PRIMARY KEY(`id`),
	CONSTRAINT `model_versions_user_version_idx` UNIQUE(`userId`,`versionName`)
);
--> statement-breakpoint
CREATE TABLE `trainingJobs` (
	`id` int AUTO_INCREMENT NOT NULL,
	`userId` int NOT NULL,
	`status` enum('running','completed','failed') NOT NULL DEFAULT 'running',
	`progress` int NOT NULL DEFAULT 0,
	`algorithm` enum('logistic_regression','gaussian_nb') NOT NULL,
	`datasetIdsJson` text NOT NULL,
	`featureSetJson` text NOT NULL,
	`modelVersionId` int,
	`errorMessage` text,
	`createdAt` timestamp NOT NULL DEFAULT (now()),
	`updatedAt` timestamp NOT NULL DEFAULT (now()) ON UPDATE CURRENT_TIMESTAMP,
	CONSTRAINT `trainingJobs_id` PRIMARY KEY(`id`)
);
