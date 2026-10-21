#!/usr/bin/env bash
# Verifies the drop-in ini disables session.upload_progress on a local PHP binary.
# Usage: mitigation/php/verify_mitigation.sh [php-binary]
set -u
PHP="${1:-php}"
DIR="$(cd "$(dirname "$0")" && pwd)"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cp "$DIR/99-php2shell-mitigation.ini" "$TMP/"
before=$("$PHP" -r 'echo ini_get("session.upload_progress.enabled") ? "on" : "off";')
# Append our scan dir to the existing ones (the ':' prefix keeps the default dirs)
after=$(PHP_INI_SCAN_DIR=":$TMP" "$PHP" -r 'echo ini_get("session.upload_progress.enabled") ? "on" : "off";')
runtime=$("$PHP" -r 'var_export(ini_set("session.upload_progress.enabled","0"));')
echo "PHP $("$PHP" -r 'echo PHP_VERSION;') | before=$before | after drop-in=$after | ini_set() at runtime returns=$runtime"
PHP_INI_SCAN_DIR=":$TMP" "$PHP" "$DIR/check_upload_progress.php"
