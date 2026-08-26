# P9 gate: export job to cef/stix/json and validate responses
$ErrorActionPreference = 'Stop'
$jobs = Invoke-RestMethod 'http://127.0.0.1:8000/api/jobs'
$j = ($jobs.jobs | Where-Object { $_.filename -like '*bruteforce*' })[0]
Write-Output ("JOB: " + $j.filename + " stage=" + $j.stage)

foreach ($fmt in @('cef', 'stix', 'json', 'csv', 'leef', 'syslog')) {
    $r = Invoke-WebRequest ("http://127.0.0.1:8000/api/export/" + $j.id + "?format=" + $fmt)
    Write-Output ("{0}: HTTP {1} bytes={2} cd={3}" -f $fmt.ToUpper(), $r.StatusCode, $r.Content.Length, $r.Headers['Content-Disposition'])
    if ($fmt -eq 'cef') {
        $line = ($r.Content -split "`n")[0]
        Write-Output ("  CEF> " + $line.Substring(0, [Math]::Min(150, $line.Length)))
    }
    if ($fmt -eq 'stix') {
        $b = $r.Content | ConvertFrom-Json
        Write-Output ("  STIX objects=" + $b.objects.Count + " pattern: " + $b.objects[0].pattern)
    }
}
