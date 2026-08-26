# P12 gate: ATT&CK kill-chain + attack graph live checks
$ErrorActionPreference = 'Continue'

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\log\logsentinel\tests\scripts\p2_gate.ps1" | Out-Null
$jobs = Invoke-RestMethod 'http://127.0.0.1:8000/api/jobs'
$j = ($jobs.jobs | Where-Object { $_.filename -like '*bruteforce*' })[0]

$t = Invoke-RestMethod ("http://127.0.0.1:8000/api/threats/" + $j.id)
$inc = $t.incidents[0]
Write-Output ("INCIDENT: " + $inc.title + " risk=" + $inc.risk_score)
$kc = $inc.killchain
Write-Output ("KILLCHAIN: " + $kc.stages_reached + "/" + $kc.total_stages + " stages (" + $kc.progress_pct + "%)")
foreach ($a in $kc.achieved) {
    Write-Output ("  STAGE " + $a.tactic + " -> " + (($a.techniques | ForEach-Object { $_.id }) -join ',') + " (evidence x" + $a.evidence_count + ")")
}
$g = Invoke-RestMethod ("http://127.0.0.1:8000/api/graph/" + $j.id)
$flagged = @($g.nodes | Where-Object { $_.flagged })
Write-Output ("GRAPH: nodes=" + $g.nodes.Count + " edges=" + $g.edges.Count + " flagged=" + ($flagged | ForEach-Object { $_.label + "(" + $_.risk + ")" }) )

# UI modules still compile
foreach ($mod in @('src/pages/Threats.jsx','src/pages/Graph.jsx')) {
    $r = Invoke-WebRequest ("http://127.0.0.1:5173/" + $mod) -TimeoutSec 20
    Write-Output ("UI_OK {0} ({1} bytes)" -f $mod, $r.Content.Length)
}
Write-Output 'P12_GATE_DONE'
