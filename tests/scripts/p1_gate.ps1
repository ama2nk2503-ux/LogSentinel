# P1 gate test v2 — PS5.1-compatible multipart via System.Net.Http
$ErrorActionPreference = 'Continue'
$base = "http://127.0.0.1:8000/api"
Add-Type -AssemblyName System.Net.Http

function Send-File($path) {
    $client = [System.Net.Http.HttpClient]::new()
    try {
        $content = [System.Net.Http.MultipartFormDataContent]::new()
        $fs = [System.IO.FileStream]::new($path, [System.IO.FileMode]::Open)
        try {
            $fc = [System.Net.Http.StreamContent]::new($fs)
            $content.Add($fc, "files", (Split-Path $path -Leaf))
            $resp = $client.PostAsync("$base/upload", $content).Result
            $body = $resp.Content.ReadAsStringAsync().Result
            return @{ code = [int]$resp.StatusCode; body = $body }
        } finally { $fs.Dispose() }
    } finally { $client.Dispose() }
}

$f = Join-Path $env:TEMP "logsentinel_p1_test.log"
if (-not (Test-Path $f)) {
    $sw = [System.IO.StreamWriter]::new($f)
    for ($i = 0; $i -lt 100000; $i++) {
        $sec = ($i % 60).ToString("00")
        $sw.WriteLine("Aug 25 10:30:$sec server sshd: Failed password for admin from 185.23.45.67")
    }
    $sw.Close()
}
Write-Output ("TESTFILE_MB: " + [math]::Round((Get-Item $f).Length / 1MB, 2))

$r = Send-File $f
Write-Output ("UPLOAD_HTTP: " + $r.code)
if ($r.code -eq 200) {
    $jid = ($r.body | ConvertFrom-Json).jobs[0].job_id
    Write-Output "JOB: $jid"
    $tries = 0
    do {
        Start-Sleep -Milliseconds 500
        $j = Invoke-RestMethod -Uri "$base/jobs/$jid"
        $tries++
    } while (($j.status -eq 'queued' -or $j.status -eq 'processing') -and $tries -lt 120)
    Write-Output ("STATUS: {0} STAGE: {1} PROGRESS: {2}" -f $j.status, $j.stage, $j.progress)
    Write-Output ("STATS: " + ($j.stats | ConvertTo-Json -Compress))
    if ($j.stats.total_lines -eq 100000) { Write-Output "LINECOUNT_OK" } else { Write-Output "LINECOUNT_MISMATCH" }
} else {
    Write-Output ("UPLOAD_BODY: " + $r.body)
}

# bad extension
$r = Send-File (Join-Path $env:TEMP "evil.exe")
if ($r.code -eq 400) { Write-Output ("BAD_EXT_REJECTED: " + $r.body) } else { Write-Output ("BAD_EXT_WRONG code=" + $r.code) }

# empty file (truly 0 bytes)
$empty = Join-Path $env:TEMP "empty.log"
[System.IO.File]::WriteAllText($empty, "")
$r = Send-File $empty
if ($r.code -eq 400) { Write-Output ("EMPTY_REJECTED: " + $r.body) } else { Write-Output ("EMPTY_WRONG code=" + $r.code) }
