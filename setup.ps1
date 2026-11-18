param([ValidateSet('Demo','Native','Research')][string]$Profile = 'Demo', [ValidateSet('3.11','3.12')][string]$PythonVersion = '3.11')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'helpers/common.ps1')
Assert-Windows
if (-not (Get-Command uv -ErrorAction SilentlyContinue)) { throw 'Install uv from https://docs.astral.sh/uv/getting-started/installation/ and Python 3.11 or 3.12, then retry.' }
Push-Location $PSScriptRoot
try {
    $arguments = @('sync','--locked','--python',$PythonVersion,'--no-python-downloads','--no-default-groups')
    if ($Profile -ne 'Demo') { $arguments += @('--extra',$Profile.ToLowerInvariant()) }
    & uv @arguments
    if ($LASTEXITCODE -ne 0) { throw 'Dependency installation failed; inspect the uv error above.' }
    & uv pip check --python (Get-LabPython)
    if ($LASTEXITCODE -ne 0) { throw 'Dependency consistency check failed.' }
    & (Get-LabPython) -c "from raneval.windows_stream import Model; m=Model('demo/windows_streaming/native-model.json'); print('Bundled model verified:', m.threshold)"
    if ($LASTEXITCODE -ne 0) { throw 'Bundled model verification failed.' }
    Write-Host "Installed $Profile profile. Start the lab with ./start.ps1"
} finally { Pop-Location }
