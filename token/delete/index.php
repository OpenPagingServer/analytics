<?php
declare(strict_types=1);

require_once __DIR__ . '/../../includes/bootstrap.php';

require_user_agent();
enforce_rate_limit('token_delete');
$row = require_token();

$stmt = analytics_pdo()->prepare("DELETE FROM analytics_tokens WHERE id = :id");
$stmt->execute(['id' => $row['id']]);

empty_response(204);
