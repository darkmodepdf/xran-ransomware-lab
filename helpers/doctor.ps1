param([switch]$SkipDocker)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-Windows
& (Get-LabPython) --version
if ($LASTEXITCODE -ne 0) { throw 'Python failed.' }
Push-Location $script:ProjectRoot
try {
    & (Get-LabPython) -c "from raneval.windows_stream import Model; Model('demo/windows_streaming/native-model.json'); print('Bundled model integrity OK')"
    if ($LASTEXITCODE -ne 0) { throw 'Model/import check failed.' }
    if (-not $SkipDocker) { Ensure-DockerReady }
    Write-Host 'Prerequisites ready. Port availability is checked at launch.'
} finally { Pop-Location }
