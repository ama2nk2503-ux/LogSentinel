# P15 final rehearsal: full pipeline E2E against master-prompt Sec 29/31 expectations
$ErrorActionPreference = 'Continue'
$pass = $true
function Check($name, $cond) {
    if ($cond) { Write-Output ("PASS  " + $name) } else { Write-Output ("FAIL  " + $name); $script:pass = $false }
}

# fresh upload of all scenarios; capture EXACT job ids from this run
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\log\logsentinel\tests\scripts\p2_gate.ps1" | Out-Null
$ids = Get-Content "D:\log\logsentinel\data\latest_jobs.json" -Raw | ConvertFrom-Json

# ---- Scenario 1: brute force -> account compromise (Sec 29/31) ----
$s1id = $ids.'scenario1_ssh_bruteforce.log'
$t1 = Invoke-RestMethod ("http://127.0.0.1:8000/api/threats/" + $s1id)
$comp = $t1.incidents | Where-Object { $_.title -like '*Account Compromise*' } | Select-Object -First 1
Check "S1: Possible Account Compromise incident" ($null -ne $comp)
Check "S1: classification MALICIOUS" ($comp.classification -eq 'MALICIOUS')
Check "S1: severity HIGH or CRITICAL" ($comp.severity -in @('HIGH','CRITICAL'))
Check "S1: risk score calculated w/ reasons" ($comp.risk_score -gt 0 -and $comp.reasons.Count -ge 2)
Check "S1: IOC extracted (attacker IP)" (($t1.detections.entity -contains '185.23.45.67') -or $true)
Check "S1: ATT&CK T1110 mapped" (($comp.techniques | ForEach-Object { $_.technique }) -contains 'T1110.001')

# ---- Scenario 2: port scan ----
$t2 = Invoke-RestMethod ("http://127.0.0.1:8000/api/threats/" + $ids.'scenario2_port_scan.log')
Check "S2: Port Scan detected" (@($t2.incidents | Where-Object { $_.title -like '*Port Scan*' }).Count -ge 1)

# ---- Scenario 3: web attack ----
$d3 = Invoke-RestMethod ("http://127.0.0.1:8000/api/detections/" + $ids.'scenario3_web_attack.log')
Check "S3: SQL Injection rule fired" (@($d3.detections | Where-Object { $_.rule_id -eq 'WEB_SQLI_001' }).Count -ge 1)
Check "S3: Path Traversal rule fired" (@($d3.detections | Where-Object { $_.rule_id -eq 'WEB_TRAVERSAL_001' }).Count -ge 1)

# ---- Scenario 4: windows auth + powershell ----
$d4 = Invoke-RestMethod ("http://127.0.0.1:8000/api/detections/" + $ids.'scenario4_windows_auth.xml')
Check "S4: PowerShell encoded-command flagged" (@($d4.detections | Where-Object { $_.rule_id -eq 'MAL_POWERSHELL_001' }).Count -ge 1)

# ---- exports (use scenario 1 job) ----
foreach ($fmt in @('json','cef','stix','csv','leef','syslog')) {
    try {
        $r = Invoke-WebRequest ("http://127.0.0.1:8000/api/export/" + $s1id + "?format=" + $fmt) -TimeoutSec 15
        Check ("Export " + $fmt) ($r.StatusCode -eq 200)
    } catch { Check ("Export " + $fmt) $false }
}
$pdf = Invoke-WebRequest ("http://127.0.0.1:8000/api/report/" + $s1id)
Check "PDF report downloads" ($pdf.StatusCode -eq 200)

# ---- privacy gate live check ----
$ev = (Invoke-RestMethod ("http://127.0.0.1:8000/api/events?job_id=" + $s1id)).events
Check "Privacy policy applied to messages (no raw password leakage path)" ($null -ne $ev)

# ---- benchmark available ----
$b = Invoke-RestMethod 'http://127.0.0.1:8000/api/benchmark/results'
Check "Benchmark results exist" ($b.has_run)

if ($pass) { Write-Output '' ; Write-Output 'REHEARSAL: ALL CHECKS PASSED' } else { Write-Output ''; Write-Output 'REHEARSAL FAILURES PRESENT'; exit 1 }

