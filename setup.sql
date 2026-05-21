CREATE TABLE IF NOT EXISTS analytics_servers (
    server_id VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    server_secret_hash CHAR(64) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    first_request_ip VARCHAR(45) NOT NULL,
    last_request_ip VARCHAR(45) NOT NULL,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (server_id),
    KEY last_seen_idx (last_seen_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS analytics_tokens (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    server_id VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    token_hash CHAR(64) NOT NULL,
    request_ip VARCHAR(45) NOT NULL,
    active TINYINT(1) NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NOT NULL,
    last_renewed_at DATETIME DEFAULT NULL,
    ended_at DATETIME DEFAULT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY token_hash_unique (token_hash),
    UNIQUE KEY server_id_unique (server_id),
    KEY server_id_idx (server_id),
    KEY request_ip_idx (request_ip),
    KEY active_expires_idx (active, expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS analytics_token_requests (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    request_ip VARCHAR(45) NOT NULL,
    request_date DATE NOT NULL,
    request_count INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY ip_date_unique (request_ip, request_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS analytics_rate_limits (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    request_ip VARCHAR(45) NOT NULL,
    endpoint VARCHAR(64) NOT NULL,
    window_start DATETIME NOT NULL,
    request_count INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (id),
    UNIQUE KEY ip_endpoint_window_unique (request_ip, endpoint, window_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS analytics_ip_timezones (
    request_ip VARCHAR(45) NOT NULL,
    timezone VARCHAR(64) NOT NULL,
    checked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (request_ip)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS analytics_release_cache (
    version VARCHAR(64) NOT NULL,
    is_release TINYINT(1) NOT NULL DEFAULT 0,
    checked_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS allowmanualsend (
    id VARCHAR(256) CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    count INT UNSIGNED NOT NULL DEFAULT 0,
    PRIMARY KEY (id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS analytics_reports (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    token_id BIGINT UNSIGNED NOT NULL,
    server_id TEXT NOT NULL,
    request_ip TEXT NOT NULL,
    report_date DATE NOT NULL,
    is_manual TINYINT(1) NOT NULL DEFAULT 0,
    received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    linux_kernel TEXT NOT NULL,
    distro TEXT NOT NULL,
    host TEXT NOT NULL,
    cpu TEXT NOT NULL,
    ram_bytes TEXT NOT NULL,
    disk_total_bytes TEXT NOT NULL,
    disk_used_bytes TEXT NOT NULL,
    ops_version TEXT NOT NULL,
    server_uptime_seconds TEXT NOT NULL,
    package_count TEXT NOT NULL,
    ip_type TEXT NOT NULL,
    private_ip_count TEXT NOT NULL,
    public_ip_count TEXT NOT NULL,
    raw_xml MEDIUMTEXT NOT NULL,
    PRIMARY KEY (id),
    KEY token_report_date_idx (token_id, report_date),
    KEY server_id_idx (server_id(256)),
    KEY report_date_idx (report_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

CREATE TABLE IF NOT EXISTS analytics_reports_unofficial (
    id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
    token_id BIGINT UNSIGNED NOT NULL,
    server_id TEXT NOT NULL,
    request_ip TEXT NOT NULL,
    report_date DATE NOT NULL,
    is_manual TINYINT(1) NOT NULL DEFAULT 0,
    received_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    linux_kernel TEXT NOT NULL,
    distro TEXT NOT NULL,
    host TEXT NOT NULL,
    cpu TEXT NOT NULL,
    ram_bytes TEXT NOT NULL,
    disk_total_bytes TEXT NOT NULL,
    disk_used_bytes TEXT NOT NULL,
    ops_version TEXT NOT NULL,
    server_uptime_seconds TEXT NOT NULL,
    package_count TEXT NOT NULL,
    ip_type TEXT NOT NULL,
    private_ip_count TEXT NOT NULL,
    public_ip_count TEXT NOT NULL,
    raw_xml MEDIUMTEXT NOT NULL,
    PRIMARY KEY (id),
    KEY token_report_date_idx (token_id, report_date),
    KEY server_id_idx (server_id(256)),
    KEY report_date_idx (report_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
