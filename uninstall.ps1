$ErrorActionPreference = 'Stop'
$InstallRoot = Join-Path $env:LOCALAPPDATA 'Programs\LANwatch'
if (Test-Path $InstallRoot) { Remove-Item -Recurse -Force $InstallRoot }
Write-Host 'LANwatch program files removed. Local data folders such as .lanwatch were left untouched.'
