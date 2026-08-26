# P13 gate: search intent API + PDF report + demo page compiles
$ErrorActionPreference = 'Continue'

# seed fresh scenario data
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "D:\log\logsentinel\tests\scripts\p2_gate.ps1" | Out-Null
$jobs = Invoke-RestMethod 'http://127.0.0.1:8000/api/jobs'
$j = ($jobs.jobs | Where-Object { $_.filename -like '*bruteforce*' })[0]

# --- Wow-D: ask-the-data ---
$body = @{ job_id = $j.id; text = "show me all high-risk authentication attacks" } | ConvertTo-Json
$q = Invoke-RestMethod 'http://127.0.0.1:8000/api/query' -Method Post -Body $body -ContentType 'application/json'
Write-Output ("QUERY chips: " + (($q.chips | ForEach-Object { "[$($_.key)=$($_.value)]" }) -join ' '))
Write-Output ("QUERY total=" + $q.total + " sample=" + $q.events[0].event_type + " sev=" + $q.events[0].severity)

# --- Wow-E: PDF report ---
$r = Invoke-WebRequest ("http://127.0.0.1:8000/api/report/" + $j.id)
$bytes = $r.RawContentLength
$magic = [System.Text.Encoding]::ASCII.GetString($r.Content[0..3])
Write-Output ("PDF: HTTP " + $r.StatusCode + " bytes=" + $bytes + " magic=" + $magic + " cd=" + $r.Headers['Content-Disposition'])

# --- UI compile checks ---
foreach ($mod in @('src/pages/Demo.jsx', 'src/components/Layout.jsx', 'src/App.jsx')) {
    $resp = Invoke-WebRequest ("http://127.0.0.1:5173/" + $mod) -TimeoutSec 20
    Write-Output ("UI_OK {0} ({1} bytes)" -f $mod, $resp.Content.Length)
}
Write-Output 'P13_GATE_DONE'
