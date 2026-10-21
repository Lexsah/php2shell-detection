/*
   php2shell-detection — YARA rules
   CVE-2026-109618 / CVE-2026-109619 (PHP session.upload_progress)
   Scope: detection only. Generic indicators, no exploit logic.
   Targets: raw HTTP request captures, web server / WAF / proxy logs,
            and memory/string dumps of PHP worker processes.
   License: MIT
*/

rule PHP2SHELL_UserAgent_Indicator
{
    meta:
        description = "Known php2shell tooling User-Agent string in HTTP traffic or logs"
        author      = "Lexsah, BG"
        reference   = "CVE-2026-109618, CVE-2026-109619"
        date        = "2026-10-21"
        severity    = "high"
        scope       = "http, logs"
    strings:
        $ua1 = "php2shell" ascii wide nocase
        $ua2 = /User-Agent:\s*[^\r\n]{0,64}php2shell/ nocase
    condition:
        any of them
}

rule PHP2SHELL_Multipart_UploadProgress_Field
{
    meta:
        description = "Multipart POST carrying the PHP session upload-progress form field (rare in legitimate traffic; hunt + triage)"
        author      = "Lexsah, BG"
        reference   = "CVE-2026-109618, CVE-2026-109619"
        date        = "2026-10-21"
        severity    = "medium"
        scope       = "http"
        false_positives = "Applications that legitimately implement PHP upload progress bars"
    strings:
        $post   = /^POST [^\r\n]+ HTTP\/[0-9.]+/
        $ct     = /Content-Type:\s*multipart\/form-data/ nocase
        $field1 = /Content-Disposition:\s*form-data;\s*name="?PHP_SESSION_UPLOAD_PROGRESS"?/ nocase
    condition:
        $post at 0 and $ct and $field1
}

rule PHP2SHELL_UploadProgress_Field_Repeated
{
    meta:
        description = "Same request contains the upload-progress field several times, or upload-progress alongside many file parts (anomalous)"
        author      = "Lexsah, BG"
        reference   = "CVE-2026-109618, CVE-2026-109619"
        date        = "2026-10-21"
        severity    = "high"
        scope       = "http"
    strings:
        $ct    = /Content-Type:\s*multipart\/form-data/ nocase
        $field = /name="?PHP_SESSION_UPLOAD_PROGRESS"?/ nocase
        $file  = /Content-Disposition:\s*form-data;[^\r\n]*filename=/ nocase
    condition:
        $ct and $field and (#field > 1 or #file > 10)
}

rule PHP2SHELL_UploadProgress_Log_Or_Memory_Strings
{
    meta:
        description = "Upload-progress markers in WAF/proxy body logs or PHP worker memory strings (hunting rule)"
        author      = "Lexsah, BG"
        reference   = "CVE-2026-109618, CVE-2026-109619"
        date        = "2026-10-21"
        severity    = "low"
        scope       = "logs, memory"
    strings:
        $s1 = "PHP_SESSION_UPLOAD_PROGRESS" ascii wide nocase
        $s2 = "upload_progress_" ascii wide
        $m  = "multipart/form-data" ascii wide nocase
    condition:
        $s1 and ($s2 or $m)
}
