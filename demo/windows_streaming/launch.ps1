param([switch]$NativeServer,[switch]$NoBrowser)
$ErrorActionPreference = 'Stop'
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '../..')).Path
. (Join-Path $projectRoot 'helpers/common.ps1')
Assert-Windows
$pythonPath = Get-LabPython
Assert-PortFree
if (-not $NativeServer) { Ensure-DockerReady }
$statePath = Join-Path $projectRoot '.local/session.json'
if (Test-Path -LiteralPath $statePath) { throw 'A session record exists. Inspect the recorded session before removing stale .local/session.json.' }
function New-SessionToken {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
    return -join ($bytes | ForEach-Object { $_.ToString('x2') })
}
$env:WINDOWS_STREAM_TOKEN = New-SessionToken
$env:WINDOWS_AGENT_TOKEN = New-SessionToken
$oldPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = Join-Path $projectRoot 'src'
$serverProcess = $null
$containerName = 'windows-stream-' + [guid]::NewGuid().ToString('N').Substring(0,12)
$containerStarted = $false
Push-Location $projectRoot
try {
    if ($NativeServer) {
        $serverScript = Join-Path $PSScriptRoot 'server.py'
        $serverProcess = Start-Process -FilePath $pythonPath -ArgumentList @('"' + $serverScript + '"') -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
    } else {
        docker build -f demo/windows_streaming/Dockerfile -t windows-stream-lab .
        if ($LASTEXITCODE -ne 0) { throw 'Docker build failed.' }
        docker run --detach --rm --read-only --cap-drop ALL --security-opt no-new-privileges --memory 128m --cpus 1 --name $containerName -p 127.0.0.1:8767:8767 -e WINDOWS_STREAM_TOKEN -e WINDOWS_AGENT_TOKEN windows-stream-lab
        if ($LASTEXITCODE -ne 0) { throw 'Docker start failed.' }
        $containerStarted = $true
    }
    $ready = $false
    $readinessDeadline = (Get-Date).AddSeconds(15)
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        $remainingSeconds = [math]::Floor(($readinessDeadline - (Get-Date)).TotalSeconds)
        if ($remainingSeconds -lt 1) { break }
        try {
            $health = Invoke-RestMethod 'http://127.0.0.1:8767/api/health' -TimeoutSec ([math]::Min(2, $remainingSeconds))
            if ($health.ok -and $health.model_available) { $ready = $true; break }
        } catch { Write-Verbose 'Waiting for inference service readiness.' }
        $remainingMilliseconds = ($readinessDeadline - (Get-Date)).TotalMilliseconds
        if ($remainingMilliseconds -gt 0) { Start-Sleep -Milliseconds ([int][math]::Min(250, $remainingMilliseconds)) }
    }
    if (-not $ready) { throw 'Inference service and bundled model did not become ready on localhost:8767 within 15 seconds.' }
    New-Item -ItemType Directory -Path (Split-Path $statePath) -Force | Out-Null
    Protect-SessionDirectory (Split-Path $statePath)
    @{ token = $env:WINDOWS_STREAM_TOKEN; container = $containerName; created = (Get-Date).ToString('o'); stop_requested = $false } | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8
    $sessionUrl = 'http://127.0.0.1:8767/#' + $env:WINDOWS_STREAM_TOKEN
    Write-Host ('Open this session URL: ' + $sessionUrl)
    Write-Host 'Agent running. Press Ctrl+C here to stop owned workers and the service.'
    if (-not $NoBrowser) { Start-Process $sessionUrl }
    & $pythonPath (Join-Path $PSScriptRoot 'agent.py')
    if ($LASTEXITCODE -ne 0) {
        $record = Get-Content -Raw -LiteralPath $statePath | ConvertFrom-Json
        if ($record.stop_requested) { Write-Host 'Service stopped; native agent closed its owned workers.' }
        else { throw 'Native agent failed; inspect the error above.' }
    }
} finally {
    if ($NativeServer -and $serverProcess) {
        try { Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8767/api/shutdown' -Headers @{ Authorization = 'Bearer ' + $env:WINDOWS_STREAM_TOKEN } -TimeoutSec 3 | Out-Null } catch { Write-Verbose 'Native service already stopped or unavailable.' }
        if (-not $serverProcess.WaitForExit(5000)) { $serverProcess.Kill(); $serverProcess.WaitForExit(5000) | Out-Null }
    }
    if ($containerStarted) {
        $present = & docker ps -aq --filter "name=^/$containerName$"
        if ($LASTEXITCODE -ne 0) { Write-Warning 'Could not inspect owned container; inspect Docker Desktop.' }
        elseif ($present) { & docker stop --time 5 $containerName | Out-Null; if ($LASTEXITCODE -ne 0) { Write-Warning 'Owned container stop failed.' } }
    }
    if (Test-Path -LiteralPath $statePath) { Remove-Item -LiteralPath $statePath }
    $env:PYTHONPATH = $oldPythonPath
    Remove-Item Env:WINDOWS_STREAM_TOKEN -ErrorAction SilentlyContinue
    Remove-Item Env:WINDOWS_AGENT_TOKEN -ErrorAction SilentlyContinue
    Pop-Location
}
