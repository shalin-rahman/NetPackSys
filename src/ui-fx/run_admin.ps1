# Self-elevate to Administrator
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "Elevating to Administrator..."
    Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    exit
}

# Use existing JAVA_HOME, or try common locations. Edit the line below if Java is elsewhere.
if (-not $env:JAVA_HOME) {
    $candidates = @(
        "C:\Program Files\Java\jdk-21",
        "C:\Program Files\Java\jdk-22",
        "C:\Program Files\Eclipse Adoptium\jdk-21*",
        "$env:USERPROFILE\.jdks\openjdk-21*",
        "$env:USERPROFILE\.jdks\openjdk-22*"
    )
    foreach ($d in $candidates) {
        $resolved = (Get-Item $d -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($resolved) { $env:JAVA_HOME = $resolved.FullName; break }
    }
}
if ($env:JAVA_HOME) { $env:PATH = "$env:JAVA_HOME\bin;$env:PATH" }

# Ensure Maven is in PATH (use 'mvn' from your normal user PATH if available)
if (!(Get-Command mvn -ErrorAction SilentlyContinue)) {
    $mavenPaths = "C:\Program Files\apache-maven-*\bin", "C:\apache-maven-*\bin", "$env:USERPROFILE\apache-maven-*\bin"
    foreach ($p in $mavenPaths) {
        $mp = (Get-Item $p -ErrorAction SilentlyContinue | Select-Object -First 1)
        if ($mp) { $env:PATH = "$($mp.FullName);$env:PATH"; break }
    }
}

# Navigate to script directory
Set-Location "$PSScriptRoot"

Write-Host "Starting NetPackSys UI as Administrator..."
Write-Host "Please check the GUI window."

mvn clean javafx:run

Write-Host "Application closed. Press any key to exit..."
$host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
