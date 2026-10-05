$ErrorActionPreference = 'Stop'

$InstallRoot = Join-Path $env:LOCALAPPDATA 'Programs\LANwatch'
$StageRoot = "$InstallRoot.new"
if (Test-Path $StageRoot) { Remove-Item -Recurse -Force $StageRoot }
New-Item -ItemType Directory -Force -Path $StageRoot | Out-Null

$PythonCommand = Get-Command py -ErrorAction SilentlyContinue
if ($PythonCommand) {
    & py -3 --version
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.11+ is required. Install Python and try again.' }
    & py -3 -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.11+ is required. Install a newer Python and try again.' }
    & py -3 -m venv (Join-Path $StageRoot 'venv')
} else {
    $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $PythonCommand) { throw 'Python 3.11+ was not found. Install Python and try again.' }
    & python --version
    & python -c "import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)"
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.11+ is required. Install a newer Python and try again.' }
    & python -m venv (Join-Path $StageRoot 'venv')
}
if ($LASTEXITCODE -ne 0) {
    Remove-Item -Recurse -Force $StageRoot
    throw 'Could not create the LANwatch virtual environment.'
}

$AppRoot = Join-Path $StageRoot 'app'
New-Item -ItemType Directory -Force -Path $AppRoot | Out-Null
Copy-Item -Recurse -Force (Join-Path $PSScriptRoot 'lanwatch') $AppRoot

$CommandFile = Join-Path $StageRoot 'lanwatch.cmd'
$Launcher = @"
@echo off
set "PYTHONPATH=%~dp0app"
"%~dp0venv\Scripts\python.exe" -m lanwatch %*
"@
$Launcher | Set-Content -Encoding Ascii $CommandFile

$VenvPython = Join-Path $StageRoot 'venv\Scripts\python.exe'
$PreviousPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = $AppRoot
& $VenvPython -c "import lanwatch; print('LANwatch ' + lanwatch.__version__)"
$env:PYTHONPATH = $PreviousPythonPath
if ($LASTEXITCODE -ne 0) {
    Remove-Item -Recurse -Force $StageRoot
    throw 'LANwatch installation self-check failed.'
}

if (Test-Path $InstallRoot) { Remove-Item -Recurse -Force $InstallRoot }
Move-Item -Path $StageRoot -Destination $InstallRoot
$CommandFile = Join-Path $InstallRoot 'lanwatch.cmd'
Write-Host 'LANwatch installed.'
Write-Host "Run it from PowerShell: & '$CommandFile' enroll"
Write-Host 'The installer did not use pip or download anything from the Internet.'
Write-Host 'Router credentials and data stay under the Windows account; no router settings were changed.'
