# Build and run the JavaFX log viewer. Requires JAVA_HOME (use setup-java.ps1 or -JdkPath).
# Use -RunAsAdmin to start as Administrator (required for live packet capture on Windows).

param(
    [string]$JdkPath = $env:JAVA_HOME,
    [switch]$RunAsAdmin
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if (-not $root) { $root = (Get-Location).Path }

if ($JdkPath) {
    $env:JAVA_HOME = $JdkPath
    $env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
}

Set-Location $root
if (-not (Test-Path "target\*.jar")) {
    Write-Host "Installing core..." -ForegroundColor Cyan
    mvn install -DskipTests -q
}

if ($RunAsAdmin) {
    Write-Host "Starting Packet Log Viewer as Administrator (for live capture)..." -ForegroundColor Cyan
    $jhome = $env:JAVA_HOME
    $cmd = "Set-Location '$root\src\ui-fx'; `$env:JAVA_HOME='$jhome'; `$env:PATH=\"`$env:JAVA_HOME\bin;`$env:PATH\"; mvn compile javafx:run"
    Start-Process powershell -Verb RunAs -ArgumentList "-NoExit", "-ExecutionPolicy", "Bypass", "-Command", $cmd
    return
}

Set-Location "$root\src\ui-fx"
Write-Host "Starting Packet Log Viewer (JavaFX). Use Simulation mode, or run with -RunAsAdmin for live capture." -ForegroundColor Cyan
mvn compile javafx:run
