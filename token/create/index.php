<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/bootstrap.php';

require_user_agent();
enforce_rate_limit('token_create');

$xml = request_xml();
$serverId = isset($xml->server_id) ? trim((string)$xml->server_id) : '';
$serverSecret = isset($xml->server_secret) ? trim((string)$xml->server_secret) : '';
$newServerSecret = null;
if ($serverId === '') {
    enforce_token_create_limit();
    $server = create_registered_server();
    $serverId = $server['server_id'];
    $newServerSecret = $server['server_secret'];
} else {
    if (strlen($serverId) > 256) {
        empty_response(400);
    }
    validate_server_id($serverId);
    if (!registered_server_id_exists($serverId)) {
        empty_response(403);
    }
    require_registered_server_secret($serverId, $serverSecret);
    touch_registered_server_id($serverId);
}

$token = make_token();
$expiresAt = gmdate('Y-m-d H:i:s', time() + (TOKEN_TTL_DAYS * 86400));
$pdo = analytics_pdo();
$pdo->beginTransaction();
try {
    $stmt = $pdo->prepare("DELETE FROM analytics_tokens WHERE server_id = :server_id OR expires_at <= UTC_TIMESTAMP() OR active = 0");
    $stmt->execute(['server_id' => $serverId]);

    $stmt = $pdo->prepare("
        INSERT INTO analytics_tokens (server_id, token_hash, request_ip, active, created_at, expires_at)
        VALUES (:server_id, :token_hash, :request_ip, 1, UTC_TIMESTAMP(), :expires_at)
    ");
    $stmt->execute([
        'server_id' => $serverId,
        'token_hash' => token_hash($token),
        'request_ip' => client_ip(),
        'expires_at' => $expiresAt,
    ]);
    $pdo->commit();
} catch (Throwable $exc) {
    if ($pdo->inTransaction()) {
        $pdo->rollBack();
    }
    throw $exc;
}

$headers = ['X-Auth-Token' => $token, 'X-Server-Id' => $serverId];
if ($newServerSecret !== null) {
    $headers['X-Server-Secret'] = $newServerSecret;
}
empty_response(204, $headers);
