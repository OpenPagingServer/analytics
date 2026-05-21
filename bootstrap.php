<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

ini_set('display_errors', '0');
ini_set('log_errors', '1');

const OPS_USER_AGENT = 'OpenPagingServer';
const TOKEN_TTL_DAYS = 8;
const TOKEN_CREATE_DAILY_LIMIT = 3;
const RATE_LIMIT_WINDOW_SECONDS = 60;
const RATE_LIMIT_MAX_REQUESTS = 120;
const GITHUB_RELEASES_URL = 'https://api.github.com/repos/OpenPagingServer/OpenPagingServer/releases';
const UNOFFICIAL_MESSAGE = 'An unofficial, unreleased, or spoofed verison is in use. Sent data will be stored but not count for public records.';
const ANALYTICS_LOG_FILE = '/tmp/openpagingserver-analytics.log';

function analytics_pdo(): PDO
{
    static $pdo = null;
    global $analyticsDsn, $analyticsDbUser, $analyticsDbPass;
    if ($pdo instanceof PDO) {
        return $pdo;
    }
    $pdo = new PDO($analyticsDsn, $analyticsDbUser, $analyticsDbPass, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_EMULATE_PREPARES => false,
    ]);
    return $pdo;
}

function empty_response(int $status, array $headers = []): void
{
    http_response_code($status);
    foreach ($headers as $name => $value) {
        header($name . ': ' . $value);
    }
    header('Content-Length: 0');
    exit;
}

function analytics_log(string $message): void
{
    $line = '[' . gmdate('Y-m-d H:i:s') . ' UTC] ' . $message . PHP_EOL;
    @file_put_contents(ANALYTICS_LOG_FILE, $line, FILE_APPEND | LOCK_EX);
}

function reject_request(int $status, string $reason, array $headers = []): void
{
    analytics_log("reject {$status}: {$reason}");
    error_log("analytics reject {$status}: {$reason}");
    empty_response($status, $headers);
}

set_exception_handler(static function (Throwable $exc): void {
    analytics_log("exception: " . $exc->getMessage() . "\n" . $exc->getTraceAsString());
    error_log($exc->getMessage() . "\n" . $exc->getTraceAsString());
    empty_response(400);
});

function require_user_agent(): void
{
    if (($_SERVER['HTTP_USER_AGENT'] ?? '') !== OPS_USER_AGENT) {
        empty_response(403);
    }
}

function client_ip(): string
{
    return $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';
}

function enforce_rate_limit(string $endpoint): void
{
    $pdo = analytics_pdo();
    $ip = client_ip();
    $window = gmdate('Y-m-d H:i:s', time() - (time() % RATE_LIMIT_WINDOW_SECONDS));
    $stmt = $pdo->prepare("
        INSERT INTO analytics_rate_limits (request_ip, endpoint, window_start, request_count)
        VALUES (:ip, :endpoint, :window_start, 1)
        ON DUPLICATE KEY UPDATE request_count = request_count + 1
    ");
    $stmt->execute(['ip' => $ip, 'endpoint' => $endpoint, 'window_start' => $window]);

    $stmt = $pdo->prepare("SELECT request_count FROM analytics_rate_limits WHERE request_ip = :ip AND endpoint = :endpoint AND window_start = :window_start");
    $stmt->execute(['ip' => $ip, 'endpoint' => $endpoint, 'window_start' => $window]);
    if ((int)$stmt->fetchColumn() > RATE_LIMIT_MAX_REQUESTS) {
        empty_response(403);
    }
}

function request_xml(): SimpleXMLElement
{
    $body = file_get_contents('php://input');
    if ($body === false || trim($body) === '') {
        empty_response(400);
    }
    libxml_use_internal_errors(true);
    $xml = simplexml_load_string($body);
    if (!$xml instanceof SimpleXMLElement) {
        empty_response(400);
    }
    return $xml;
}

function xml_text(SimpleXMLElement $xml, string $name, int $maxLength = 4096): string
{
    if (!isset($xml->{$name})) {
        reject_request(400, "missing XML field {$name}");
    }
    $value = trim((string)$xml->{$name});
    if ($value === '' || strlen($value) > $maxLength) {
        reject_request(400, "bad XML field {$name}");
    }
    return $value;
}

function validate_server_id(string $serverId): void
{
    if (!preg_match('/^[A-Za-z0-9]{256}$/', $serverId)) {
        reject_request(400, 'invalid server_id format');
    }
}

function make_server_id(): string
{
    $alphabet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $id = '';
    $max = strlen($alphabet) - 1;
    for ($i = 0; $i < 256; $i++) {
        $id .= $alphabet[random_int(0, $max)];
    }
    return $id;
}

function make_server_secret(): string
{
    return bin2hex(random_bytes(32));
}

function server_secret_hash(string $serverSecret): string
{
    return hash('sha256', $serverSecret);
}

function validate_server_secret(string $serverSecret): void
{
    if (!preg_match('/^[A-Fa-f0-9]{64}$/', $serverSecret)) {
        reject_request(400, 'invalid server_secret format');
    }
}

function registered_server_id_exists(string $serverId): bool
{
    $stmt = analytics_pdo()->prepare("SELECT 1 FROM analytics_servers WHERE server_id = :server_id LIMIT 1");
    $stmt->execute(['server_id' => $serverId]);
    return (bool)$stmt->fetchColumn();
}

function create_registered_server(): array
{
    $pdo = analytics_pdo();
    do {
        $serverId = make_server_id();
        $serverSecret = make_server_secret();
        $stmt = $pdo->prepare("
            INSERT IGNORE INTO analytics_servers (server_id, server_secret_hash, first_request_ip, last_request_ip, created_at, last_seen_at)
            VALUES (:server_id, :server_secret_hash, :first_request_ip, :last_request_ip, UTC_TIMESTAMP(), UTC_TIMESTAMP())
        ");
        $stmt->execute([
            'server_id' => $serverId,
            'server_secret_hash' => server_secret_hash($serverSecret),
            'first_request_ip' => client_ip(),
            'last_request_ip' => client_ip(),
        ]);
    } while ($stmt->rowCount() !== 1);

    return ['server_id' => $serverId, 'server_secret' => $serverSecret];
}

function require_registered_server_secret(string $serverId, string $serverSecret): void
{
    validate_server_secret($serverSecret);
    $stmt = analytics_pdo()->prepare("SELECT server_secret_hash FROM analytics_servers WHERE server_id = :server_id LIMIT 1");
    $stmt->execute(['server_id' => $serverId]);
    $hash = $stmt->fetchColumn();
    if (!is_string($hash) || !hash_equals($hash, server_secret_hash($serverSecret))) {
        empty_response(403);
    }
}

function touch_registered_server_id(string $serverId): void
{
    $pdo = analytics_pdo();
    $stmt = $pdo->prepare("
        UPDATE analytics_servers
        SET last_request_ip = :last_request_ip, last_seen_at = UTC_TIMESTAMP()
        WHERE server_id = :server_id
    ");
    $stmt->execute([
        'server_id' => $serverId,
        'last_request_ip' => client_ip(),
    ]);
}

function make_token(): string
{
    return bin2hex(random_bytes(32));
}

function delete_expired_tokens(): void
{
    analytics_pdo()->exec("DELETE FROM analytics_tokens WHERE expires_at <= UTC_TIMESTAMP() OR active = 0");
}

function token_hash(string $token): string
{
    return hash('sha256', $token);
}

function bearer_token(): string
{
    $header = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
    if (!preg_match('/^Bearer\s+([A-Fa-f0-9]{64})$/', $header, $matches)) {
        empty_response(401);
    }
    return $matches[1];
}

function require_token(): array
{
    $pdo = analytics_pdo();
    delete_expired_tokens();
    $hash = token_hash(bearer_token());
    $stmt = $pdo->prepare("
        SELECT * FROM analytics_tokens
        WHERE token_hash = :token_hash AND active = 1 AND expires_at > UTC_TIMESTAMP()
        LIMIT 1
    ");
    $stmt->execute(['token_hash' => $hash]);
    $row = $stmt->fetch();
    if (!$row) {
        empty_response(401);
    }
    return $row;
}

function enforce_token_create_limit(): void
{
    $pdo = analytics_pdo();
    $ip = client_ip();
    $today = gmdate('Y-m-d');
    $stmt = $pdo->prepare("
        INSERT INTO analytics_token_requests (request_ip, request_date, request_count)
        VALUES (:ip, :request_date, 1)
        ON DUPLICATE KEY UPDATE request_count = request_count + 1
    ");
    $stmt->execute(['ip' => $ip, 'request_date' => $today]);

    $stmt = $pdo->prepare("SELECT request_count FROM analytics_token_requests WHERE request_ip = :ip AND request_date = :request_date");
    $stmt->execute(['ip' => $ip, 'request_date' => $today]);
    if ((int)$stmt->fetchColumn() > TOKEN_CREATE_DAILY_LIMIT) {
        empty_response(403, ['Retry-After' => '86400']);
    }
}

function resolve_ip_timezone(string $ip): string
{
    global $analyticsDefaultTimezone, $analyticsTimezoneLookupUrl;
    $pdo = analytics_pdo();
    $stmt = $pdo->prepare("SELECT timezone FROM analytics_ip_timezones WHERE request_ip = :ip AND checked_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 30 DAY)");
    $stmt->execute(['ip' => $ip]);
    $cached = $stmt->fetchColumn();
    if (is_string($cached) && in_array($cached, timezone_identifiers_list(), true)) {
        return $cached;
    }

    $timezone = $analyticsDefaultTimezone ?: 'UTC';
    if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) && !empty($analyticsTimezoneLookupUrl)) {
        $url = sprintf($analyticsTimezoneLookupUrl, rawurlencode($ip));
        $context = stream_context_create(['http' => ['timeout' => 3, 'user_agent' => OPS_USER_AGENT]]);
        $json = @file_get_contents($url, false, $context);
        $data = is_string($json) ? json_decode($json, true) : null;
        if (is_array($data) && ($data['status'] ?? '') === 'success' && in_array((string)($data['timezone'] ?? ''), timezone_identifiers_list(), true)) {
            $timezone = (string)$data['timezone'];
        }
    }

    $stmt = $pdo->prepare("
        INSERT INTO analytics_ip_timezones (request_ip, timezone, checked_at)
        VALUES (:ip, :timezone, UTC_TIMESTAMP())
        ON DUPLICATE KEY UPDATE timezone = VALUES(timezone), checked_at = VALUES(checked_at)
    ");
    $stmt->execute(['ip' => $ip, 'timezone' => $timezone]);
    return $timezone;
}

function ip_local_now(): DateTimeImmutable
{
    $timezone = resolve_ip_timezone(client_ip());
    return new DateTimeImmutable('now', new DateTimeZone($timezone));
}

function is_five_am(DateTimeImmutable $now): bool
{
    return $now->format('H:i') === '05:00';
}

function consume_manual_send_allowance(string $serverId): void
{
    $pdo = analytics_pdo();
    $pdo->beginTransaction();
    try {
        $stmt = $pdo->prepare("SELECT `count` FROM allowmanualsend WHERE id = :id FOR UPDATE");
        $stmt->execute(['id' => $serverId]);
        $count = $stmt->fetchColumn();
        if ($count === false || (int)$count < 1) {
            $pdo->rollBack();
            empty_response(403);
        }

        if ((int)$count === 1) {
            $stmt = $pdo->prepare("DELETE FROM allowmanualsend WHERE id = :id");
            $stmt->execute(['id' => $serverId]);
        } else {
            $stmt = $pdo->prepare("UPDATE allowmanualsend SET `count` = `count` - 1 WHERE id = :id");
            $stmt->execute(['id' => $serverId]);
        }
        $pdo->commit();
    } catch (Throwable $exc) {
        if ($pdo->inTransaction()) {
            $pdo->rollBack();
        }
        throw $exc;
    }
}

function require_manual_send_allowance(string $serverId): void
{
    $stmt = analytics_pdo()->prepare("SELECT `count` FROM allowmanualsend WHERE id = :id LIMIT 1");
    $stmt->execute(['id' => $serverId]);
    $count = $stmt->fetchColumn();
    if ($count === false || (int)$count < 1) {
        reject_request(403, "manual upload not authorized for server_id " . substr($serverId, 0, 12));
    }
}

function validate_number_text(string $value): void
{
    if (!preg_match('/^\d+$/', $value)) {
        reject_request(400, 'invalid numeric report field');
    }
}

function validate_report_values(array $values): void
{
    if (!preg_match('/^\d+\.\d+\.\d+$/', $values['ops_version'])) {
        reject_request(400, 'invalid ops_version format');
    }
    foreach (['ram_bytes', 'disk_total_bytes', 'disk_used_bytes', 'server_uptime_seconds', 'package_count', 'private_ip_count', 'public_ip_count'] as $name) {
        validate_number_text($values[$name]);
    }
    if (!in_array($values['ip_type'], ['private', 'public', 'mixed'], true)) {
        reject_request(400, 'invalid ip_type');
    }
}

function is_release_version(string $version): bool
{
    $pdo = analytics_pdo();
    $stmt = $pdo->prepare("SELECT is_release FROM analytics_release_cache WHERE version = :version AND checked_at > DATE_SUB(UTC_TIMESTAMP(), INTERVAL 1 DAY)");
    $stmt->execute(['version' => $version]);
    $cached = $stmt->fetchColumn();
    if ($cached !== false) {
        return (bool)$cached;
    }

    $isRelease = false;
    $context = stream_context_create(['http' => ['timeout' => 5, 'user_agent' => OPS_USER_AGENT]]);
    $json = @file_get_contents(GITHUB_RELEASES_URL, false, $context);
    $releases = is_string($json) ? json_decode($json, true) : null;
    if (is_array($releases)) {
        foreach ($releases as $release) {
            $tag = ltrim((string)($release['tag_name'] ?? ''), 'vV');
            if ($tag === $version && empty($release['draft'])) {
                $isRelease = true;
                break;
            }
        }
    }

    $stmt = $pdo->prepare("
        INSERT INTO analytics_release_cache (version, is_release, checked_at)
        VALUES (:version, :is_release, UTC_TIMESTAMP())
        ON DUPLICATE KEY UPDATE is_release = VALUES(is_release), checked_at = VALUES(checked_at)
    ");
    $stmt->execute(['version' => $version, 'is_release' => $isRelease ? 1 : 0]);
    return $isRelease;
}
