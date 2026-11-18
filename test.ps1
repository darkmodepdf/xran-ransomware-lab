param([ValidateSet('Windows','All')][string]$Suite = 'Windows')
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'helpers/common.ps1')
Push-Location $PSScriptRoot
try {
    $pattern = if ($Suite -eq 'Windows') { 'test_windows*.py' } else { 'test_*.py' }
    & (Get-LabPython) -m unittest discover -s tests -p $pattern -v
    if ($LASTEXITCODE -ne 0) { throw "$Suite test suite failed." }
} finally { Pop-Location }
