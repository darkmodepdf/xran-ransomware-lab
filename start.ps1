param([switch]$NativeServer,[switch]$NoBrowser)
$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'demo/windows_streaming/launch.ps1') -NativeServer:$NativeServer -NoBrowser:$NoBrowser
