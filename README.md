# php2shell-detection — CVE-2026-109618 / CVE-2026-109619

![license](https://img.shields.io/badge/license-MIT-blue)
![scope](https://img.shields.io/badge/scope-detection%20%26%20mitigation-green)
![rules](https://img.shields.io/badge/rules-YARA%20%7C%20Sigma%20%7C%20Suricata%20%7C%20ModSecurity%20%7C%20Falco-informational)

Blue-team detection rules and a temporary hardening for **CVE-2026-109618** and **CVE-2026-109619**,
the PHP `session.upload_progress` issues publicly referred to as **php2shell**.

> **Scope: detection & mitigation only. This repository intentionally omits exploit details.**
> No proof-of-concept, payloads, or exploitation walkthroughs are included or linked. Test fixtures are synthetic.

## TL;DR for defenders

1. **Mitigate now** — set `session.upload_progress.enabled = Off` at the server level ([mitigation/php](mitigation/php)).
   It is a `PHP_INI_PERDIR` setting: `ini_set()` / `auto_prepend_file` **cannot** change it, and the upload-progress
   handler runs while the request body is parsed, i.e. before any of your PHP code executes.
2. **Detect** — deploy the YARA / Sigma / Suricata / ModSecurity / Falco rules below (alert-only by default).
3. **Patch** — upgrade to the fixed PHP release from your distribution or php.net as soon as it is available.
   The mitigation in this repo is **temporary until the official patch** is deployed.

## Are you exposed?

Most applications never use upload progress, so disabling it is usually free. You are potentially exposed when:

- PHP's `session` extension is loaded (default in most builds), **and**
- `session.upload_progress.enabled` is `On` (the PHP default), **and**
- a PHP endpoint is reachable that accepts `multipart/form-data` POST requests (any PHP script does).

Check quickly:

```bash
php -r 'var_dump(ini_get("session.upload_progress.enabled"));'   # CLI view
php mitigation/php/check_upload_progress.php; echo $?              # 0 = mitigated, 1 = exposed
```

The CLI may load a different ini set than php-fpm / mod_php. For the web SAPI, deploy
`check_upload_progress.php` temporarily, request it once, then **delete it**.
Refer to the official CVE records / PHP advisories for the exact affected version ranges.

## Mitigation

| Deployment | File | Where it goes |
|---|---|---|
| Any SAPI (conf.d) | [`99-php2shell-mitigation.ini`](mitigation/php/99-php2shell-mitigation.ini) | `/etc/php/8.x/{fpm,apache2,cli}/conf.d/` (Debian/Ubuntu), `/etc/php.d/` (RHEL), `/usr/local/etc/php/conf.d/` (official Docker images) |
| PHP-FPM pool (non-overridable) | [`fpm/zz-php2shell-mitigation.pool.conf`](mitigation/php/fpm/zz-php2shell-mitigation.pool.conf) | append to each pool, e.g. `/etc/php/8.4/fpm/pool.d/www.conf` |
| Apache + mod_php | [`apache/php2shell-mitigation.conf`](mitigation/php/apache/php2shell-mitigation.conf) | `conf-available/` then `a2enconf` |
| Docker | [`docker/Dockerfile.example`](mitigation/php/docker/Dockerfile.example) | `COPY` the ini; the build fails if the setting is not effective |
| Shared hosting (CGI/FPM only) | [`user.ini.example`](mitigation/php/user.ini.example) | `.user.ini` in the docroot (honoured after `user_ini.cache_ttl`) |

Reload afterwards: `systemctl reload php8.4-fpm` / `systemctl reload apache2` / rebuild the container.
Verify with `mitigation/php/verify_mitigation.sh` (CLI) and `check_upload_progress.php` (web).

If nothing in your stack uses PHP sessions at all, not loading the `session` extension is an even stronger option.

**Why not a PHP extension or `auto_prepend_file`?** The setting is evaluated during request startup / body parsing,
before userland code runs, and it is not changeable at runtime. A server-level ini value is the smallest correct fix
and is trivial to revert once you are patched.

## Detection rules

| Path | Engine | What it flags |
|---|---|---|
| [`rules/yara/php2shell_upload_progress.yar`](rules/yara/php2shell_upload_progress.yar) | YARA | `php2shell` User-Agent; multipart POST carrying `PHP_SESSION_UPLOAD_PROGRESS`; repeated/abnormal upload-progress requests; hunting strings for body logs & PHP worker memory |
| [`rules/sigma/`](rules/sigma) | Sigma | webserver: `php2shell*` UA, POST referencing `PHP_SESSION_UPLOAD_PROGRESS`; linux process_creation: shell spawned by php-fpm / php-cgi / Apache |
| [`rules/suricata/php2shell.rules`](rules/suricata/php2shell.rules) | Suricata 7 | SIDs 910961801-803: UA, multipart + upload-progress field, repeated field |
| [`rules/modsecurity/php2shell.conf`](rules/modsecurity/php2shell.conf) | ModSecurity v2/v3 | IDs 9109618-9109620, `pass,log` (switch to `deny` after tuning) |
| [`rules/falco/php_worker_shell.yaml`](rules/falco/php_worker_shell.yaml) | Falco | shell / downloader spawned by a PHP worker |
| [`rules/auditd/php_worker_exec.rules`](rules/auditd/php_worker_exec.rules) | auditd | execve by the web-server UID for hunting |

**Tuning notes**

- `PHP_SESSION_UPLOAD_PROGRESS` is the **default** field name (`session.upload_progress.name`). If you changed it, add your name to the rules; an attacker can only use the name your server is configured with.
- Legitimate upload-progress bars exist but are rare; baseline for a few days before blocking.
- Access logs normally do not contain request bodies: the Sigma webserver rules catch the UA and query-string variants; body inspection belongs to the WAF/IDS rules.
- User-Agent strings are trivially changed. Treat UA rules as a high-confidence/low-coverage signal and the body + process rules as the durable ones.

## Tests

```bash
tests/run_tests.sh      # prints PASS/FAIL per check, exit code 0 when everything passes
```

The suite uses **synthetic fixtures only** ([`tests/fixtures`](tests/fixtures)) and checks both match and no-match cases:

- YARA compile + match/no-match
- Sigma: `sigma check`, conversion round-trip, and a small evaluator against access-log fixtures
- Suricata: `suricata -T`, then replay of synthetic pcaps built from the fixtures
- ModSecurity: a throw-away Apache + mod_security2 instance on 127.0.0.1 (static files, no PHP)
- PHP mitigation: CLI drop-in, runtime `ini_set()` refusal, and PHP-FPM pool with/without the fix

Requirements (Debian/Ubuntu): `yara suricata apache2 libapache2-mod-security2 php-cli php-fpm libfcgi-bin`,
plus `pip install sigma-cli pysigma-backend-splunk scapy pyyaml`. Missing tools are reported as `SKIP`.

## Authors

- **Lexsah** ([@Lexsah](https://github.com/Lexsah)) — research, rules, mitigation
- **BG** (assistant) — co-researcher / contributor

## Disclaimer

Provided as-is for defensive purposes. Validate in staging before production. Contributions (new log formats,
false-positive reports, rule ports) are welcome via issues and pull requests.

<sub>Keywords: CVE-2026-109618, CVE-2026-109619, php2shell, PHP session.upload_progress, PHP_SESSION_UPLOAD_PROGRESS, detection, YARA, Sigma, Suricata, ModSecurity, Falco, blue team, mitigation, php-fpm hardening</sub>
