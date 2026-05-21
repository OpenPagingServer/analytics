<?php
declare(strict_types=1);

require_once __DIR__ . '/../includes/bootstrap.php';

require_user_agent();
enforce_rate_limit('report');
$tokenRow = require_token();
$localNow = ip_local_now();
$xmlBody = file_get_contents('php://input');
if ($xmlBody === false || trim($xmlBody) === '') {
    reject_request(400, 'empty report XML body');
}
libxml_use_internal_errors(true);
$xml = simplexml_load_string($xmlBody);
if (!$xml instanceof SimpleXMLElement) {
    reject_request(400, 'invalid report XML');
}

$fields = [
    'server_id',
    'linux_kernel',
    'distro',
    'host',
    'cpu',
    'ram_bytes',
    'disk_total_bytes',
    'disk_used_bytes',
    'ops_version',
    'server_uptime_seconds',
    'package_count',
    'ip_type',
    'private_ip_count',
    'public_ip_count',
];

$values = [];
foreach ($fields as $field) {
    $values[$field] = xml_text($xml, $field);
}
validate_server_id($values['server_id']);
if (!hash_equals((string)$tokenRow['server_id'], $values['server_id'])) {
    reject_request(403, 'report server_id does not match auth token');
}
validate_report_values($values);

$isScheduledReport = is_five_am($localNow);
if (!$isScheduledReport) {
    require_manual_send_allowance($values['server_id']);
}

$official = is_release_version($values['ops_version']);
$table = $official ? 'analytics_reports' : 'analytics_reports_unofficial';
$reportDate = $localNow->format('Y-m-d');

if ($isScheduledReport) {
    $alreadyReported = analytics_pdo()->prepare("
        SELECT 1 FROM analytics_reports WHERE token_id = :official_token_id AND report_date = :official_report_date
        UNION
        SELECT 1 FROM analytics_reports_unofficial WHERE token_id = :unofficial_token_id AND report_date = :unofficial_report_date
        LIMIT 1
    ");
    $alreadyReported->execute([
        'official_token_id' => $tokenRow['id'],
        'official_report_date' => $reportDate,
        'unofficial_token_id' => $tokenRow['id'],
        'unofficial_report_date' => $reportDate,
    ]);
    if ($alreadyReported->fetchColumn()) {
        reject_request(403, 'scheduled report already exists for this token/date');
    }
}

$sql = "
    INSERT INTO {$table} (
        token_id, server_id, request_ip, report_date, received_at,
        linux_kernel, distro, host, cpu, ram_bytes, disk_total_bytes, disk_used_bytes,
        ops_version, server_uptime_seconds, package_count, ip_type, private_ip_count,
        public_ip_count, raw_xml
    ) VALUES (
        :token_id, :server_id, :request_ip, :report_date, UTC_TIMESTAMP(),
        :linux_kernel, :distro, :host, :cpu, :ram_bytes, :disk_total_bytes, :disk_used_bytes,
        :ops_version, :server_uptime_seconds, :package_count, :ip_type, :private_ip_count,
        :public_ip_count, :raw_xml
    )
";

try {
    $stmt = analytics_pdo()->prepare($sql);
    $stmt->execute([
        'token_id' => $tokenRow['id'],
        'server_id' => $values['server_id'],
        'request_ip' => client_ip(),
        'report_date' => $reportDate,
        'linux_kernel' => $values['linux_kernel'],
        'distro' => $values['distro'],
        'host' => $values['host'],
        'cpu' => $values['cpu'],
        'ram_bytes' => $values['ram_bytes'],
        'disk_total_bytes' => $values['disk_total_bytes'],
        'disk_used_bytes' => $values['disk_used_bytes'],
        'ops_version' => $values['ops_version'],
        'server_uptime_seconds' => $values['server_uptime_seconds'],
        'package_count' => $values['package_count'],
        'ip_type' => $values['ip_type'],
        'private_ip_count' => $values['private_ip_count'],
        'public_ip_count' => $values['public_ip_count'],
        'raw_xml' => $xmlBody,
    ]);
    if (!$isScheduledReport) {
        consume_manual_send_allowance($values['server_id']);
    }
} catch (PDOException $exc) {
    if ($exc->getCode() === '23000') {
        reject_request(403, 'duplicate report rejected');
    }
    throw $exc;
}

$headers = $official ? [] : ['X-Message' => UNOFFICIAL_MESSAGE];
empty_response(204, $headers);
