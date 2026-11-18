param([string]$Out)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'common.ps1')
Assert-Windows
$python = Get-LabPython
if (-not $Out) { $Out = Join-Path $script:ProjectRoot ('runs/native-reproduction-' + (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,8)) }
$Out = [System.IO.Path]::GetFullPath($Out)
if (Test-Path -LiteralPath $Out) { throw 'Output directory already exists; choose a fresh directory.' }
& $python -c 'import numpy, scipy, sklearn'
if ($LASTEXITCODE -ne 0) { throw 'Install the Native profile with ./setup.ps1 -Profile Native first.' }
$bundle = Join-Path $Out 'native-model.json'
Push-Location $script:ProjectRoot
try {
    & $python scripts/train_windows_native.py all --experiment v2 --out $Out --bundle $bundle
    if ($LASTEXITCODE -ne 0) { throw "Native reproduction failed; inspect partial evidence in $Out" }
    Write-Host "Separate experimental bundle: $bundle"
} finally { Pop-Location }
