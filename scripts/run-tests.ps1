# Run core and UI-FX tests. Requires JAVA_HOME (use setup-java.ps1 or -JdkPath).

param([string]$JdkPath = $env:JAVA_HOME)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $root) { $root = (Get-Location).Path }

if ($JdkPath) {
    $env:JAVA_HOME = $JdkPath
    $env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
}

Write-Host "Running core tests..." -ForegroundColor Cyan
Set-Location $root
mvn clean test -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Installing core for UI-FX..." -ForegroundColor Cyan
mvn install -DskipTests -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "Running UI-FX tests..." -ForegroundColor Cyan
Set-Location "$root\src\ui-fx"
mvn test -q
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host "All tests passed." -ForegroundColor Green
