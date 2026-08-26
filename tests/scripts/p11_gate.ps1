# P11 gate: UI serves + all page modules transpile + proxy reaches backend
$ErrorActionPreference = 'Continue'
$fail = $false

# backend must be up
try { Invoke-RestMethod 'http://127.0.0.1:8000/api/health' -TimeoutSec 5 | Out-Null } catch { Write-Output 'BACKEND_DOWN'; $fail = $true }

foreach ($mod in @('src/index.css','src/main.jsx','src/App.jsx','src/components/Layout.jsx',
                   'src/components/JobPicker.jsx','src/pages/Upload.jsx','src/pages/Dashboard.jsx',
                   'src/pages/Explorer.jsx','src/pages/Threats.jsx')) {
    try {
        $r = Invoke-WebRequest ("http://127.0.0.1:5173/" + $mod) -TimeoutSec 15
        if ($r.StatusCode -eq 200) { Write-Output ("OK   {0} ({1} bytes)" -f $mod, $r.Content.Length) }
        else { Write-Output ("FAIL {0} code={1}" -f $mod, $r.StatusCode); $fail = $true }
    } catch {
        Write-Output ("FAIL {0}: {1}" -f $mod, $_.Exception.Message); $fail = $true
    }
}

# proxy check through vite -> fastapi
try {
    $h = Invoke-RestMethod 'http://127.0.0.1:5173/api/health' -TimeoutSec 10
    Write-Output ("PROXY_OK status=" + $h.status)
} catch { Write-Output 'PROXY_FAIL'; $fail = $true }

if ($fail) { exit 1 } else { Write-Output 'P11_GATE_PASS' }
