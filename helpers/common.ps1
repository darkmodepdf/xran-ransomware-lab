$ErrorActionPreference = 'Stop'
$script:ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
function Get-LabPython {
    $path = Join-Path $script:ProjectRoot '.venv/Scripts/python.exe'
    if (-not (Test-Path -LiteralPath $path)) { throw 'Run ./setup.ps1 first (Python 3.11 or 3.12 and uv required).' }
    return $path
}
function Assert-Windows {
    if ($env:OS -ne 'Windows_NT') { throw 'The local native agent requires Windows 11.' }
}
function Assert-PortFree {
    $probe = New-Object System.Net.Sockets.TcpClient
    try { $probe.Connect('127.0.0.1',8767); $busy = $true } catch { $busy = $false } finally { $probe.Dispose() }
    if ($busy) { throw 'Localhost port 8767 is already in use. No service was stopped. Use ./stop.ps1 only for a session launched by this checkout.' }
}
function Test-DockerReady {
    # Windows PowerShell turns native stderr into terminating errors under Stop.
    # Daemon startup failure is expected here and must reach the bounded retry.
    $ErrorActionPreference = 'Continue'
    & docker info --format '{{.OSType}}' 2>$null | Out-Null
    return $LASTEXITCODE -eq 0
}
function Protect-SessionDirectory([string]$Path) {
    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
    $acl = New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
    Set-Acl -LiteralPath $Path -AclObject $acl
}
function Ensure-DockerReady {
    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) { throw 'Install Docker Desktop and select Linux containers, then retry.' }
    if (-not (Test-DockerReady)) {
        $desktop = Join-Path $env:ProgramFiles 'Docker/Docker/Docker Desktop.exe'
        if (-not (Test-Path -LiteralPath $desktop)) { throw 'Docker daemon unavailable; start your installed Docker engine.' }
        Start-Process -FilePath $desktop -WindowStyle Hidden
        $deadline = (Get-Date).AddSeconds(120)
        do { Start-Sleep -Seconds 2; if (Test-DockerReady) { break } } while ((Get-Date) -lt $deadline)
    }
    if (-not (Test-DockerReady)) { throw 'Docker did not become ready in 120 seconds. Open Docker Desktop, resolve its startup error, and retry.' }
    $kind = & docker info --format '{{.OSType}}'
    if ($LASTEXITCODE -ne 0 -or $kind -ne 'linux') { throw 'Select Linux containers in Docker Desktop, then retry. Engine settings were not changed.' }
}
