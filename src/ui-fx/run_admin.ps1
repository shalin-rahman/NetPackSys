# Self-elevate to Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Elevating to Administrator..."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# Set JAVA_HOME
$env:JAVA_HOME = "C:\Users\HabiburRahmanShalin\.jdks\openjdk-25.0.1"

# Ensure Maven is in PATH
if (!(Get-Command mvn -ErrorAction SilentlyContinue)) {
    # Attempt to add standard Maven path if not found
    $env:PATH = "$env:JAVA_HOME\bin;C:\apache-maven-3.9.11-bin\apache-maven-3.9.11\bin;$env:PATH"
} else {
    $env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
}

# Navigate to script directory
Set-Location "$PSScriptRoot"

Write-Host "Starting NetPackSys UI as Administrator..."
Write-Host "Please check the GUI window."

mvn clean javafx:run

Write-Host "Application closed. Press any key to exit..."
$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
