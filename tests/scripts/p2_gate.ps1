# P2 gate: upload 4 sample formats, verify detection + parse stats
param([string]$Port = 8000)
$ErrorActionPreference = 'Continue'
Add-Type -AssemblyName System.Net.Http
$base = "http://127.0.0.1:$Port/api"
$samples = @(
    "scenario1_ssh_bruteforce.log",
    "scenario2_port_scan.log",
    "scenario3_web_attack.log",
    "scenario4_windows_auth.xml"
)

$client = [System.Net.Http.HttpClient]::new()
$map = @{}
foreach ($f in $samples) {
    $path = Join-Path "D:\log\logsentinel\samples" $f
    $mc = [System.Net.Http.MultipartFormDataContent]::new()
    $fs = [System.IO.FileStream]::new($path, [System.IO.FileMode]::Open)
    $sc = [System.Net.Http.StreamContent]::new($fs)
    $mc.Add($sc, "files", $f)
    $resp = $client.PostAsync("$base/upload", $mc).Result
    if ([int]$resp.StatusCode -ne 200) {
        Write-Output ("UPLOAD_FAIL {0}: {1}" -f $f, $resp.StatusCode)
        $fs.Close(); continue
    }
    $jid = ($resp.Content.ReadAsStringAsync().Result | ConvertFrom-Json).jobs[0].job_id
    $map[$f] = $jid
    $n = 0
    do {
        Start-Sleep -Milliseconds 400
        $j = Invoke-RestMethod ("$base/jobs/" + $jid)
        $n++
    } while (($j.status -eq 'queued' -or $j.status -eq 'processing') -and $n -lt 100)
    Write-Output ("{0} -> format='{1}' conf={2}% status={3} lines={4} parsed={5} types={6}" -f `
        $f, $j.detected_format, $j.format_confidence, $j.status, $j.stats.total_lines, $j.stats.parsed_lines, ($j.stats.event_types | ConvertTo-Json -Compress))
    $fs.Close()
}
$client.Dispose()

# persist exact job-id map for downstream gate scripts
$map | ConvertTo-Json -Depth 3 | Set-Content -Path "D:\log\logsentinel\data\latest_jobs.json" -Encoding UTF8
Write-Output ("JOB_MAP_SAVED: " + $map.Count + " entries")


