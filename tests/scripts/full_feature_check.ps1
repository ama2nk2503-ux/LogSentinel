# FULL FEATURE VERIFICATION SWEEP
$ErrorActionPreference = 'Continue'
$base = "http://127.0.0.1:8000/api"
$results = @()
function Check($name, $cond) {
    $script:results += [pscustomobject]@{ Feature = $name; Status = $(if ($cond) {'PASS'} else {'FAIL'}) }
}

# 0. server up?
try { Invoke-RestMethod "$base/health" -TimeoutSec 5 | Out-Null } catch { Write-Output "SERVER_DOWN - start uvicorn first"; exit 1 }

# 1. upload all scenarios fresh (uses exact-id map)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\log\logsentinel\tests\scripts\p2_gate.ps1" | Out-Null
$ids = Get-Content "D:\log\logsentinel\data\latest_jobs.json" -Encoding UTF8 -Raw | ConvertFrom-Json
Check "Ingestion: multi-file upload + jobs" (@($ids.PSObject.Properties).Count -eq 4)

# 2. format detection per file
$fmts = @{}
foreach ($p in $ids.PSObject.Properties) {
    $j = Invoke-RestMethod ("$base/jobs/" + $p.Value)
    $fmts[$p.Name] = @{ fmt = $j.detected_format; conf = $j.format_confidence }
}
Check "Format detection: syslog SSH (>=85%)" ($fmts.'scenario1_ssh_bruteforce.log'.conf -ge 85)
Check "Format detection: firewall KV" ($fmts.'scenario2_port_scan.log'.fmt -eq 'firewall')
Check "Format detection: apache" ($fmts.'scenario3_web_attack.log'.fmt -like '*Apache*')
Check "Format detection: windows xml" ($fmts.'scenario4_windows_auth.xml'.fmt -like '*Windows*')

# 3. normalization + provenance
$ev = (Invoke-RestMethod ("$base/events?job_id=" + $ids.'scenario1_ssh_bruteforce.log')).events[0]
Check "Normalization: ISO timestamp + src_ip + username" ($ev.ts -match '^\d{4}-' -and $ev.src_ip -eq '185.23.45.67' -and $ev.username -eq 'admin')
$d1 = Invoke-RestMethod ("$base/events/" + $ev.event_id)
Check "Provenance mapping stored" (@($d1.mappings.PSObject.Properties).Count -gt 3)

# 4. IOC extraction
$iocs = Invoke-RestMethod ("$base/ioc/" + $ids.'scenario1_ssh_bruteforce.log')
Check "IOC extraction: attacker IP found" (@($iocs.iocs | Where-Object { $_.value -eq '185.23.45.67' }).Count -ge 1)

# 5. threat detection rules
$dets1 = Invoke-RestMethod ("$base/detections/" + $ids.'scenario1_ssh_bruteforce.log')
Check "Rules: BRUTE_FORCE_001" (@($dets1.detections | Where-Object rule_id -eq 'BRUTE_FORCE_001').Count -ge 1)
Check "Rules: credential abuse follow-up reason" ((@($dets1.detections | Where-Object rule_id -eq 'BRUTE_FORCE_001')[0].reasons) -join ' ' -match 'successful')
$dets3 = Invoke-RestMethod ("$base/detections/" + $ids.'scenario3_web_attack.log')
Check "Rules: WEB_SQLI + WEB_TRAVERSAL + WEB_XSS" (@($dets3.detections | Where-Object { $_.rule_id -in @('WEB_SQLI_001','WEB_TRAVERSAL_001','WEB_XSS_001') }).Count -eq 3)
$dets4 = Invoke-RestMethod ("$base/detections/" + $ids.'scenario4_windows_auth.xml')
Check "Rules: MAL_POWERSHELL (windows)" (@($dets4.detections | Where-Object rule_id -eq 'MAL_POWERSHELL_001').Count -ge 1)

# 6. correlation + classification + risk
$t1 = Invoke-RestMethod ("$base/threats/" + $ids.'scenario1_ssh_bruteforce.log')
$inc = $t1.incidents | Where-Object { $_.title -like '*Account Compromise*' } | Select-Object -First 1
Check "Correlation: Account Compromise incident" ($null -ne $inc)
Check "Classification MALICIOUS + severity HIGH+" ($inc.classification -eq 'MALICIOUS' -and $inc.severity -in @('HIGH','CRITICAL'))
Check "Risk scoring w/ transparent reasons" ($inc.risk_score -gt 50 -and @($inc.reasons).Count -ge 3)
Check "Attack timeline present" (@($inc.timeline).Count -ge 5)

# 7. ATT&CK kill-chain
Check "ATT&CK: T1110 mapped + killchain stages" ((@($inc.techniques | ForEach-Object technique) -contains 'T1110.001') -and $inc.killchain.stages_reached -ge 2)

# 8. attack graph
$g = Invoke-RestMethod ("$base/graph/" + $ids.'scenario1_ssh_bruteforce.log')
Check "Attack graph: flagged nodes exist" (@($g.nodes | Where-Object flagged).Count -ge 1)

# 9. privacy policy engine
$pol = Invoke-RestMethod "$base/policy"
Check "Privacy policy loadable" ($pol.policy.EMAIL -in @('MASK','REDACT'))
$up = Invoke-RestMethod "$base/policy" -Method Put -Body (@{ policy = @{ EMAIL = 'REDACT' } } | ConvertTo-Json) -ContentType 'application/json'
Check "Privacy policy hot-update" ($up.policy.EMAIL -eq 'REDACT')
Invoke-RestMethod "$base/policy" -Method Put -Body (@{ policy = @{ EMAIL = 'MASK' } } | ConvertTo-Json) -ContentType 'application/json' | Out-Null

# 10. ask-the-data search
$q = Invoke-RestMethod "$base/query" -Method Post -Body (@{ job_id = $ids.'scenario1_ssh_bruteforce.log'; text = 'show me all high-risk authentication attacks' } | ConvertTo-Json) -ContentType 'application/json'
Check "Ask-the-Data: chips + correct results" ($q.total -ge 3 -and (@($q.chips | Where-Object key -eq 'severity')).Count -eq 1)

# 11. intel
$intel = Invoke-RestMethod ("$base/intel/" + $ids.'scenario1_ssh_bruteforce.log')
Check "Threat intel: indicators aggregated" ($intel.indicators.Count -ge 1)
Check "Threat intel: report has recommendation" ($intel.reports[0].recommended_response.Length -gt 20)

# 12. exports x6
foreach ($f in @('json','cef','stix','csv','leef','syslog')) {
    try { $r = Invoke-WebRequest ("http://127.0.0.1:8000/api/export/" + $ids.'scenario1_ssh_bruteforce.log' + "?format=$f") -TimeoutSec 15; Check "Export $f" ($r.StatusCode -eq 200) }
    catch { Check "Export $f" $false }
}

# 13. pdf report
try { $pdf = Invoke-WebRequest ("http://127.0.0.1:8000/api/report/" + $ids.'scenario1_ssh_bruteforce.log'); Check "PDF threat report" ($pdf.StatusCode -eq 200 -and $pdf.RawContentLength -gt 2000) } catch { Check "PDF threat report" $false }

# 14. real-time stream sim
try {
    $s = Invoke-RestMethod "$base/stream/start" -Method Post -Body (@{ interval_ms=200; lines_per_tick=10 } | ConvertTo-Json) -ContentType 'application/json'
    Start-Sleep 4
    $st = Invoke-RestMethod "$base/stream/status"
    $live = Invoke-RestMethod ("$base/events?job_id=" + $st.job_id + '&page_size=1')
    Check "Stream simulator emits + persists events" ($st.running -and $live.total -gt 20)
    Invoke-RestMethod "$base/stream/stop" -Method Post | Out-Null
} catch { Check "Stream simulator emits + persists events" $false }

# 15. benchmark
try { $b = Invoke-RestMethod "$base/benchmark/run" -Method Post -TimeoutSec 120; Check "Benchmark metrics computed" ($b.performance.throughput_lps -gt 100 -and $b.redaction.redaction_effectiveness -eq 1.0) } catch { Check "Benchmark metrics computed" $false }

# 16. dashboard (the fixed one)
try { $dash = Invoke-RestMethod ("$base/dashboard/" + $ids.'scenario1_ssh_bruteforce.log'); Check "Dashboard aggregates + charts" ($dash.cards.total_events -gt 0 -and $dash.charts.severity.Count -ge 1) } catch { Check "Dashboard aggregates + charts" $false }

# ---- report ----
Write-Output ""
$fail = ($results | Where-Object Status -eq 'FAIL').Count
$results | Format-Table -AutoSize
Write-Output ("TOTAL: " + $results.Count + " | PASS: " + ($results.Count - $fail) + " | FAIL: " + $fail)

