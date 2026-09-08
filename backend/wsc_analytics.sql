-- MariaDB Schema for WSC Analytics & Industry Benchmark Registry
-- Database: `wsc_analytics`

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `projects`
--

CREATE TABLE IF NOT EXISTS `projects` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `uuid` varchar(100) NOT NULL,
  `domain` varchar(1024) NOT NULL,
  `api_secret` varchar(100) NOT NULL,
  `local_aes_key` varchar(100) NOT NULL,
  `registered_ip` varchar(45) NOT NULL,
  `platform` varchar(50) NOT NULL DEFAULT 'wordpress',
  `status` int(11) NOT NULL DEFAULT 0 COMMENT '0= active, 10= pending, 999= blocked',
  -- Industry Vertical Taxonomy Fields (Google NLP Content Hierarchy)
  `vertical` varchar(255) DEFAULT NULL COMMENT 'e.g. /Shopping/Apparel/Footwear',
  `vertical_label` varchar(255) DEFAULT NULL COMMENT 'e.g. E-Commerce: Fashion & Apparel',
  `vertical_confidence` decimal(5,4) DEFAULT 0.0000,
  `vertical_source` varchar(50) DEFAULT 'nlp_centroid' COMMENT 'google_nlp_api, nlp_centroid, manual_override',
  `vertical_classified_at` datetime DEFAULT NULL,
  `created` datetime NOT NULL,
  `updated` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uuid` (`uuid`),
  KEY `status` (`status`),
  KEY `idx_vertical` (`vertical`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `wsc_verticals` (Taxonomie & k-Anonymität-Katalog)
--

CREATE TABLE IF NOT EXISTS `wsc_verticals` (
  `id` int(11) NOT NULL AUTO_INCREMENT,
  `vertical_path` varchar(255) NOT NULL,
  `label` varchar(255) NOT NULL,
  `parent_path` varchar(255) DEFAULT NULL,
  `active_nodes` int(11) NOT NULL DEFAULT 0,
  `k_status` varchar(50) NOT NULL DEFAULT 'pending_k_threshold' COMMENT 'active (>=25 nodes), pending_k_threshold (<25 nodes)',
  `updated_at` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_vertical_path` (`vertical_path`),
  KEY `idx_k_status` (`k_status`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- --------------------------------------------------------

--
-- Tabellenstruktur für Tabelle `wsc_benchmark_snapshots` (Pre-Computed Benchmark Cache)
--

CREATE TABLE IF NOT EXISTS `wsc_benchmark_snapshots` (
  `id` bigint(20) NOT NULL AUTO_INCREMENT,
  `vertical_path` varchar(255) NOT NULL,
  `period_days` int(11) NOT NULL DEFAULT 30,
  `calculated_at` datetime NOT NULL,
  `active_nodes` int(11) NOT NULL,
  `k_threshold_satisfied` tinyint(1) NOT NULL DEFAULT 1,
  `metrics_json` longtext NOT NULL COMMENT 'Canonical JSON with p50, p75, p90, IQR per metric',
  `created_at` datetime NOT NULL DEFAULT current_timestamp(),
  PRIMARY KEY (`id`),
  UNIQUE KEY `idx_vertical_period` (`vertical_path`, `period_days`),
  KEY `idx_calculated_at` (`calculated_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
