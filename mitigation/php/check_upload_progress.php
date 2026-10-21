<?php
// php2shell-detection — mitigation check for CVE-2026-109618 / CVE-2026-109619.
// CLI:  php check_upload_progress.php            (exit 0 = mitigated, 1 = exposed)
// Web:  deploy temporarily, request once, then DELETE this file.
declare(strict_types=1);

$enabled = filter_var(ini_get('session.upload_progress.enabled'), FILTER_VALIDATE_BOOLEAN);
$session = extension_loaded('session');
$status  = (!$session || !$enabled) ? 'MITIGATED' : 'EXPOSED';

$report = [
    'php_version'                     => PHP_VERSION,
    'sapi'                            => PHP_SAPI,
    'session_extension_loaded'        => $session,
    'session.upload_progress.enabled' => $enabled ? 'On' : 'Off',
    'session.upload_progress.cleanup' => ini_get('session.upload_progress.cleanup'),
    'status'                          => $status,
];

if (PHP_SAPI !== 'cli') {
    header('Content-Type: text/plain');
}
foreach ($report as $k => $v) {
    printf("%-34s %s\n", $k . ':', is_bool($v) ? ($v ? 'yes' : 'no') : (string)$v);
}
if (PHP_SAPI === 'cli') {
    exit($status === 'MITIGATED' ? 0 : 1);
}
