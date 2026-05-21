<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/bootstrap.php';

require_user_agent();
enforce_rate_limit('token_renew');
$row = require_token();

$xml = request_xml();
$serverId = xml_text($xml, 'server_id', 256);
validate_server_id($serverId);
if (!hash_equals((string)$row['server_id'], $serverId)) {
    empty_response(403);
}

$token = make_token();
$expiresAt = gmdate('Y-m-d H:i:s', time() + (TOKEN_TTL_DAYS * 86400));
$pdo = analytics_pdo();
$stmt = $pdo->prepare("DELETE FROM analytics_tokens WHERE server_id = :server_id AND id <> :id");
$stmt->execute(['server_id' => $serverId, 'id' => $row['id']]);

$stmt = $pdo->prepare("
    UPDATE analytics_tokens
    SET token_hash = :token_hash,
        request_ip = :request_ip,
        last_renewed_at = UTC_TIMESTAMP(),
        expires_at = :expires_at
    WHERE id = :id
");
$stmt->execute([
    'token_hash' => token_hash($token),
    'request_ip' => client_ip(),
    'expires_at' => $expiresAt,
    'id' => $row['id'],
]);

empty_response(204, ['X-Auth-Token' => $token]);
