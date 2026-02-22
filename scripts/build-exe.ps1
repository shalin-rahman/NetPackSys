# Build NetPackSys.exe (always requests Administrator when run).
# Requires: core built and installed (mvn install in root), JAVA_HOME set.
# Output: src\ui-fx\target\dist\NetPackSys.exe and lib\ folder (keep both together).

param([string]$JdkPath = $env:JAVA_HOME)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $root) { $root = (Get-Location).Path }

if ($JdkPath) {
    $env:JAVA_HOME = $JdkPath
    $env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
}

Write-Host "Building core (if needed)..." -ForegroundColor Cyan
Set-Location $root
if (-not (Test-Path "target\*.jar")) {
    mvn install -DskipTests -q
}

Write-Host "Building NetPackSys.exe (run as Administrator)..." -ForegroundColor Cyan
Set-Location "$root\src\ui-fx"
mvn package -DskipTests -q

$exe = "$root\src\ui-fx\target\dist\NetPackSys.exe"
$lib = "$root\src\ui-fx\target\dist\lib"
if (Test-Path $exe) {
    Write-Host "Done. EXE and lib folder:" -ForegroundColor Green
    Write-Host "  $root\src\ui-fx\target\dist\NetPackSys.exe" -ForegroundColor White
    Write-Host "  $lib" -ForegroundColor White
    Write-Host "Copy the whole 'dist' folder to use the app; double-click the exe (UAC will ask for admin)." -ForegroundColor Yellow
} else {
    Write-Host "Build may have failed; exe not found at $exe" -ForegroundColor Red
    exit 1
}
