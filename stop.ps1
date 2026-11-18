$ErrorActionPreference = 'Stop'
$statePath = Join-Path $PSScriptRoot '.local/session.json'
if (-not (Test-Path -LiteralPath $statePath)) { Write-Host 'No owned session is recorded for this checkout.'; return }
$state = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
try {
    $state.stop_requested = $true
    $state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
    Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8767/api/shutdown' -Headers @{ Authorization = 'Bearer ' + $state.token } -TimeoutSec 5 | Out-Null
    Write-Host 'Requested authenticated shutdown. The launcher will close its owned workers and service.'
} catch {
    if (Test-Path -LiteralPath $statePath) { $state.stop_requested = $false; $state | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8 }
    throw 'Owned session shutdown failed. No process was killed; inspect the launcher and remove stale .local/session.json only after confirming it has ended.'
}
