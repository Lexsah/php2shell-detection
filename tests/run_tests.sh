#!/usr/bin/env bash
# php2shell-detection — rule & mitigation test-suite (synthetic fixtures only).
# Exit code 0 = all PASS. Sections whose tool is missing are reported as SKIP.
set -u
export PATH="$PATH:/usr/sbin:/sbin"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FX="$ROOT/tests/fixtures"
WORK="$(mktemp -d)"; trap 'cleanup' EXIT
PY="${PYTHON:-$( [ -x "$ROOT/.venv/bin/python" ] && echo "$ROOT/.venv/bin/python" || echo python3)}"
SIGMA="${SIGMA:-$( [ -x "$ROOT/.venv/bin/sigma" ] && echo "$ROOT/.venv/bin/sigma" || command -v sigma || true)}"
PASS=0; FAIL=0; SKIP=0
APACHE_PID=""; FPM_PIDS=""
cleanup() { [ -n "$APACHE_PID" ] && kill "$APACHE_PID" 2>/dev/null; for p in $FPM_PIDS; do kill "$p" 2>/dev/null; done; rm -rf "$WORK"; }
ok()   { echo "PASS  $*"; PASS=$((PASS+1)); }
ko()   { echo "FAIL  $*"; FAIL=$((FAIL+1)); }
skip() { echo "SKIP  $*"; SKIP=$((SKIP+1)); }
expect() { # expect <0|1 expected-exit> <label> <cmd...>
  local want="$1" label="$2"; shift 2
  "$@" >/dev/null 2>&1; local rc=$?; [ "$rc" -ne 0 ] && rc=1
  [ "$rc" -eq "$want" ] && ok "$label" || ko "$label (rc=$rc want=$want)"
}

echo "== YARA =="
if command -v yara >/dev/null; then
  Y="$ROOT/rules/yara/php2shell_upload_progress.yar"
  expect 0 "yara: rules compile" yara -w "$Y" /dev/null
  yhit() { yara -w "$Y" "$2" | awk '{print $1}' | grep -qx "$1"; }
  expect 0 "yara: UA rule matches access.log php2shell-109619"  yhit PHP2SHELL_UserAgent_Indicator "$FX/malicious/access_php2shell_ua.log"
  expect 0 "yara: UA rule matches raw HTTP php2shell UA"         yhit PHP2SHELL_UserAgent_Indicator "$FX/malicious/http_php2shell_ua.txt"
  expect 0 "yara: multipart+upload_progress matches raw HTTP"    yhit PHP2SHELL_Multipart_UploadProgress_Field "$FX/malicious/http_upload_progress_multipart.txt"
  expect 0 "yara: hunting strings rule matches raw HTTP"         yhit PHP2SHELL_UploadProgress_Log_Or_Memory_Strings "$FX/malicious/http_upload_progress_multipart.txt"
  expect 1 "yara: repeated-field rule silent on single field"     yhit PHP2SHELL_UploadProgress_Field_Repeated "$FX/malicious/http_upload_progress_multipart.txt"
  for f in "$FX"/benign/*; do
    expect 1 "yara: no match on benign $(basename "$f")" test -n "$(yara -w "$Y" "$f")"
  done
else skip "yara not installed"; fi

echo "== SIGMA =="
if [ -n "$SIGMA" ]; then
  expect 0 "sigma check (sigma-cli) on rules/sigma" "$SIGMA" check "$ROOT/rules/sigma"
  expect 0 "sigma convert to splunk (syntax round-trip)" "$SIGMA" convert -t splunk --without-pipeline "$ROOT/rules/sigma/web_php2shell_user_agent.yml" "$ROOT/rules/sigma/web_php_upload_progress_post.yml"
else skip "sigma-cli not installed (YAML-only checks below)"; fi
for r in "$ROOT"/rules/sigma/*.yml; do
  expect 0 "sigma: YAML + required keys $(basename "$r")" "$PY" -c "
import yaml,sys,uuid; d=yaml.safe_load(open('$r'))
assert all(k in d for k in ('title','id','status','logsource','detection','level')); uuid.UUID(d['id'])
assert 'condition' in d['detection']"
done
S="$ROOT/rules/sigma"; E="$ROOT/tests/sigma_eval.py"
expect 0 "sigma: UA rule matches access.log php2shell-109619"     "$PY" "$E" "$S/web_php2shell_user_agent.yml" "$FX/malicious/access_php2shell_ua.log"
expect 1 "sigma: UA rule silent on benign access.log"             "$PY" "$E" "$S/web_php2shell_user_agent.yml" "$FX/benign/access_benign.log"
expect 0 "sigma: upload-progress POST rule matches query fixture"  "$PY" "$E" "$S/web_php_upload_progress_post.yml" "$FX/malicious/access_upload_progress_query.log"
expect 1 "sigma: upload-progress POST rule silent on benign log"   "$PY" "$E" "$S/web_php_upload_progress_post.yml" "$FX/benign/access_benign.log"

echo "== SURICATA =="
if command -v suricata >/dev/null && "$PY" -c "import scapy" 2>/dev/null; then
  SR="$ROOT/rules/suricata/php2shell.rules"
  cat > "$WORK/suri.yaml" <<YAML
%YAML 1.1
---
vars:
  address-groups: {HOME_NET: "[192.0.2.0/24]", EXTERNAL_NET: "!\$HOME_NET", HTTP_SERVERS: "\$HOME_NET"}
  port-groups: {HTTP_PORTS: "80"}
default-log-dir: $WORK
outputs:
  - fast: {enabled: yes, filename: fast.log, append: yes}
app-layer:
  protocols:
    http: {enabled: yes}
classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config
YAML
  expect 0 "suricata -T: rules load" suricata -T -c "$WORK/suri.yaml" -S "$SR" -l "$WORK"
  suri_sids() { # suri_sids <fixture> -> prints sids
    local d="$WORK/run_$(basename "$1")"; mkdir -p "$d"
    "$PY" "$ROOT/tests/make_pcap.py" "$1" "$d/t.pcap" >/dev/null 2>&1
    suricata -c "$WORK/suri.yaml" -S "$SR" -r "$d/t.pcap" -l "$d" -k none >/dev/null 2>&1
    grep -o '\[1:[0-9]*:' "$d/fast.log" 2>/dev/null | cut -d: -f2 | sort -u | tr '\n' ' '
  }
  s=$(suri_sids "$FX/malicious/http_upload_progress_multipart.txt")
  [[ " $s" == *" 910961802 "* ]] && ok "suricata: sid 910961802 fires on multipart upload_progress" || ko "suricata: sid 910961802 (got: $s)"
  [[ " $s" != *" 910961803 "* ]] && ok "suricata: sid 910961803 silent on single field" || ko "suricata: 910961803 fired unexpectedly"
  s=$(suri_sids "$FX/malicious/http_php2shell_ua.txt")
  [[ " $s" == *" 910961801 "* ]] && ok "suricata: sid 910961801 fires on php2shell UA" || ko "suricata: sid 910961801 (got: $s)"
  for f in "$FX"/benign/http_*.txt; do
    s=$(suri_sids "$f"); [ -z "$s" ] && ok "suricata: no alert on benign $(basename "$f")" || ko "suricata: alert on benign $(basename "$f"): $s"
  done
else skip "suricata or scapy missing (rules not runtime-tested)"; fi

echo "== MODSECURITY (Apache mod_security2, DetectionOnly-style pass,log) =="
MODDIR=/usr/lib/apache2/modules
if command -v apache2 >/dev/null && [ -f "$MODDIR/mod_security2.so" ]; then
  PORT=18089; mkdir -p "$WORK/www" "$WORK/apache"; echo ok > "$WORK/www/index.html"
  for p in upload.php login.php avatar.php; do echo ok > "$WORK/www/$p"; done
  cat > "$WORK/apache/httpd.conf" <<CONF
ServerRoot "$WORK/apache"
PidFile "$WORK/apache/httpd.pid"
Listen 127.0.0.1:$PORT
ServerName localhost
LoadModule mpm_event_module $MODDIR/mod_mpm_event.so
LoadModule authz_core_module $MODDIR/mod_authz_core.so
LoadModule mime_module $MODDIR/mod_mime.so
LoadModule unique_id_module $MODDIR/mod_unique_id.so
LoadModule security2_module $MODDIR/mod_security2.so
TypesConfig /etc/mime.types
DocumentRoot "$WORK/www"
<Directory "$WORK/www">
  Require all granted
</Directory>
ErrorLog "$WORK/apache/error.log"
LogLevel warn
SecRuleEngine On
SecRequestBodyAccess On
SecAuditEngine RelevantOnly
SecAuditLogParts ABHZ
SecAuditLog "$WORK/apache/audit.log"
SecTmpDir "$WORK/apache"
SecDataDir "$WORK/apache"
Include "$ROOT/rules/modsecurity/php2shell.conf"
CONF
  expect 0 "apache2 -t with php2shell.conf loaded" apache2 -t -f "$WORK/apache/httpd.conf"
  apache2 -f "$WORK/apache/httpd.conf" -DFOREGROUND >/dev/null 2>&1 & APACHE_PID=$!
  for i in $(seq 1 30); do (echo > /dev/tcp/127.0.0.1/$PORT) 2>/dev/null && break; sleep 0.2; done
  send() { "$PY" - "$1" "$PORT" <<'PYS'
import socket,sys
d=open(sys.argv[1],"rb").read().replace(b"Host: victim.example",b"Host: localhost").replace(b"Host: www.example",b"Host: localhost")
s=socket.create_connection(("127.0.0.1",int(sys.argv[2])));s.sendall(d);s.settimeout(3)
try: s.recv(4096)
except Exception: pass
PYS
  }
  mids() { : > "$WORK/apache/error.log"; send "$1"; sleep 0.5; grep -o '\[id "[0-9]*"\]' "$WORK/apache/error.log" | grep -o '[0-9]*' | sort -u | tr '\n' ' '; }
  m=$(mids "$FX/malicious/http_php2shell_ua.txt");            [[ " $m" == *" 9109618 "* ]] && ok "modsec: id 9109618 fires on php2shell UA" || ko "modsec: 9109618 (got: $m)"
  m=$(mids "$FX/malicious/http_upload_progress_multipart.txt"); [[ " $m" == *" 9109619 "* ]] && ok "modsec: id 9109619 fires on upload_progress field" || ko "modsec: 9109619 (got: $m)"
  [[ " $m" == *" 9109620 "* ]] && ok "modsec: id 9109620 (raw body fallback) fires" || ko "modsec: 9109620 (got: $m)"
  for f in "$FX"/benign/http_*.txt; do
    m=$(mids "$f"); [ -z "$m" ] && ok "modsec: no alert on benign $(basename "$f")" || ko "modsec: alert on benign $(basename "$f"): $m"
  done
else skip "apache2 + mod_security2 not installed (rules not runtime-tested)"; fi

echo "== FALCO / AUDITD (static) =="
expect 0 "falco rule YAML parses + has rule/condition" "$PY" -c "
import yaml; d=yaml.safe_load(open('$ROOT/rules/falco/php_worker_shell.yaml'))
r=[x for x in d if 'rule' in x]; assert r and all('condition' in x and 'output' in x for x in r)"
expect 0 "auditd rules: only -a always,exit lines" bash -c "! grep -vE '^(#|$|-a always,exit )' '$ROOT/rules/auditd/php_worker_exec.rules'"

echo "== PHP MITIGATION =="
if command -v php >/dev/null; then
  expect 0 "CLI: drop-in ini turns session.upload_progress.enabled Off" "$ROOT/mitigation/php/verify_mitigation.sh"
  expect 1 "CLI: control (no mitigation) reports EXPOSED (test is sensitive)" php -n -d extension=session "$ROOT/mitigation/php/check_upload_progress.php"
  expect 1 "CLI: ini_set() cannot change it at runtime (PERDIR)" php -r 'exit(ini_set("session.upload_progress.enabled","0")===false?1:0);'
  FPM="$(command -v php-fpm8.5 || command -v php-fpm8.4 || command -v php-fpm || true)"
  if [ -n "$FPM" ] && command -v cgi-fcgi >/dev/null; then
    for mode in mitigated control; do
      d="$WORK/fpm_$mode"; mkdir -p "$d"
      { echo "[global]"; echo "pid = $d/fpm.pid"; echo "error_log = $d/fpm.log"; echo "[t]"
        echo "listen = $d/fpm.sock"; echo "pm = static"; echo "pm.max_children = 1"
        [ "$mode" = mitigated ] && cat "$ROOT/mitigation/php/fpm/zz-php2shell-mitigation.pool.conf"; } > "$d/fpm.conf"
      "$FPM" -n -d extension=session -F -y "$d/fpm.conf" >/dev/null 2>&1 & FPM_PIDS="$FPM_PIDS $!"
      for i in $(seq 1 30); do [ -S "$d/fpm.sock" ] && break; sleep 0.2; done
      out=$(SCRIPT_FILENAME="$ROOT/mitigation/php/check_upload_progress.php" REQUEST_METHOD=GET cgi-fcgi -bind -connect "$d/fpm.sock" 2>/dev/null)
      if [ "$mode" = mitigated ]; then
        grep -q "status:.*MITIGATED" <<<"$out" && ok "FPM: pool php_admin_flag -> MITIGATED" || ko "FPM: mitigated pool output: $out"
      else
        grep -q "status:.*EXPOSED" <<<"$out" && ok "FPM: control pool -> EXPOSED (test is sensitive)" || ko "FPM: control pool output: $out"
      fi
    done
  else skip "php-fpm / cgi-fcgi not installed"; fi
else skip "php not installed"; fi

echo
echo "RESULT: PASS=$PASS FAIL=$FAIL SKIP=$SKIP"
[ "$FAIL" -eq 0 ] && { echo "OVERALL: PASS"; exit 0; } || { echo "OVERALL: FAIL"; exit 1; }
