# Single-point run: tests (with coverage) + JavaFX UI launch AS ADMINISTRATOR.
# Usage:  .\scripts\run-all.ps1 [-JdkPath "C:\path\to\jdk"]
# The script self-elevates to Administrator so live packet capture works.
# Tests run for both core and ui-fx modules. JaCoCo coverage reports are
# generated and displayed before the GUI starts.

param([string]$JdkPath = $env:JAVA_HOME)

# -- Self-elevate to Administrator --------------------------------------------
if (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] 'Administrator')) {
    Write-Host 'Elevating to Administrator...' -ForegroundColor Yellow
    $argList = '-NoProfile -ExecutionPolicy Bypass -File "' + $PSCommandPath + '"'
    if ($JdkPath) {
        $argList += ' -JdkPath "' + $JdkPath + '"'
    }
    Start-Process powershell.exe -Verb RunAs -ArgumentList $argList
    exit
}

Write-Host 'Running as Administrator.' -ForegroundColor Green

# -- Ensure no previous instances are running ----------------------------------
Write-Host 'Closing any running NetPackSys instances...' -ForegroundColor DarkGray
Get-Process java -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowTitle -match 'NetPackSys' -or $_.CommandLine -match 'javafx:run' } | Stop-Process -Force -ErrorAction SilentlyContinue

$ErrorActionPreference = 'Stop'

# Resolve project root (parent of scripts/)
$root = Split-Path -Parent $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }

# -- Java setup ---------------------------------------------------------------
if ($JdkPath) {
    $env:JAVA_HOME = $JdkPath
    $env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
}
if (-not (Get-Command java -ErrorAction SilentlyContinue)) {
    $candidates = @(
        "$env:USERPROFILE\.jdks\openjdk-*",
        'C:\Program Files\Eclipse Adoptium\jdk-*',
        'C:\Program Files\Java\jdk-*'
    )
    foreach ($pattern in $candidates) {
        $found = Get-Item $pattern -ErrorAction SilentlyContinue |
                 Where-Object { $_.Name -notlike '*.intellij*' } |
                 Sort-Object Name -Descending | Select-Object -First 1
        if ($found) {
            $env:JAVA_HOME = $found.FullName
            $env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
            break
        }
    }
}

# -- Maven setup (elevated shell may lose PATH) -------------------------------
if (-not (Get-Command mvn -ErrorAction SilentlyContinue)) {
    $mavenCandidates = @(
        'C:\apache-maven-*\bin',
        'C:\Program Files\apache-maven-*\bin',
        "$env:USERPROFILE\apache-maven-*\bin"
    )
    foreach ($mp in $mavenCandidates) {
        $mvnDir = Get-Item $mp -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($mvnDir) {
            $env:PATH = $mvnDir.FullName + ';' + $env:PATH
            break
        }
    }
}

Write-Host "Using JAVA_HOME = $env:JAVA_HOME" -ForegroundColor DarkGray

$separator = '==============================================================='

# -- Step 1: Core module - test -----------------------------------------------
Write-Host ''
Write-Host $separator -ForegroundColor Cyan
Write-Host '  Step 1/4 - Running Core Tests' -ForegroundColor Cyan
Write-Host $separator -ForegroundColor Cyan
Set-Location $root
mvn clean test
if ($LASTEXITCODE -ne 0) {
    Write-Host 'Core tests FAILED. Aborting.' -ForegroundColor Red
    Read-Host 'Press Enter to exit'
    exit $LASTEXITCODE
}
Write-Host 'Core tests PASSED.' -ForegroundColor Green

# -- Step 2: Install core into local repo -------------------------------------
Write-Host ''
Write-Host $separator -ForegroundColor Cyan
Write-Host '  Step 2/4 - Installing Core for UI-FX' -ForegroundColor Cyan
Write-Host $separator -ForegroundColor Cyan
mvn install -DskipTests -q
if ($LASTEXITCODE -ne 0) {
    Write-Host 'Core install FAILED. Aborting.' -ForegroundColor Red
    Read-Host 'Press Enter to exit'
    exit $LASTEXITCODE
}

# -- Step 3: UI-FX module - test + coverage -----------------------------------
Write-Host ''
Write-Host $separator -ForegroundColor Cyan
Write-Host '  Step 3/4 - Running UI-FX Tests with JaCoCo Coverage' -ForegroundColor Cyan
Write-Host $separator -ForegroundColor Cyan
Set-Location "$root\src\ui-fx"
mvn clean test
if ($LASTEXITCODE -ne 0) {
    Write-Host 'UI-FX tests FAILED. Aborting.' -ForegroundColor Red
    Read-Host 'Press Enter to exit'
    exit $LASTEXITCODE
}
Write-Host 'UI-FX tests PASSED.' -ForegroundColor Green

# -- Display coverage summary -------------------------------------------------
Write-Host ''
Write-Host $separator -ForegroundColor Yellow
Write-Host '  Test Coverage Report - JaCoCo' -ForegroundColor Yellow
Write-Host $separator -ForegroundColor Yellow

$coverageReport = "$root\src\ui-fx\target\site\jacoco\index.html"
$coverageCsv    = "$root\src\ui-fx\target\site\jacoco\jacoco.csv"

$divider = '  -----------------------------------------------------------'

if (Test-Path $coverageCsv) {
    Write-Host ''
    Write-Host '  Package Coverage Breakdown:' -ForegroundColor White
    Write-Host $divider -ForegroundColor DarkGray
    $csv = Import-Csv $coverageCsv
    $totalMissed = 0; $totalCovered = 0
    foreach ($row in $csv) {
        $missed  = [int]$row.LINE_MISSED
        $covered = [int]$row.LINE_COVERED
        $total   = $missed + $covered
        $totalMissed  += $missed
        $totalCovered += $covered
        if ($total -gt 0) {
            $pct = [math]::Round(($covered / $total) * 100, 1)
        } else {
            $pct = 0
        }
        $pkg = $row.PACKAGE
        if ([string]::IsNullOrEmpty($pkg)) { $pkg = '(default)' }

        $color = if ($pct -ge 90) { 'Green' } elseif ($pct -ge 70) { 'Yellow' } else { 'Red' }
        $line = '    ' + $pkg.PadRight(30) + $pct.ToString().PadLeft(6) + '%  ' + $covered + '/' + $total + ' lines'
        Write-Host $line -ForegroundColor $color
    }
    $grandTotal = $totalMissed + $totalCovered
    if ($grandTotal -gt 0) {
        $overallPct = [math]::Round(($totalCovered / $grandTotal) * 100, 1)
    } else {
        $overallPct = 0
    }
    Write-Host $divider -ForegroundColor DarkGray
    $overallColor = if ($overallPct -ge 90) { 'Green' } elseif ($overallPct -ge 70) { 'Yellow' } else { 'Red' }
    $overallLine = '    ' + 'OVERALL'.PadRight(30) + $overallPct.ToString().PadLeft(6) + '%  ' + $totalCovered + '/' + $grandTotal + ' lines'
    Write-Host $overallLine -ForegroundColor $overallColor
    Write-Host ''
}

if (Test-Path $coverageReport) {
    Write-Host "  Full HTML report: $coverageReport" -ForegroundColor DarkCyan
    Start-Process $coverageReport
} else {
    Write-Host '  No HTML coverage report found' -ForegroundColor DarkGray
}

# -- Step 4: Launch the JavaFX UI (as Administrator for live capture) ---------
Write-Host ''
Write-Host $separator -ForegroundColor Cyan
Write-Host '  Step 4/4 - Launching NetPackSys JavaFX UI (Administrator)' -ForegroundColor Cyan
Write-Host $separator -ForegroundColor Cyan
Write-Host '  Running as Administrator - live packet capture is enabled.' -ForegroundColor Green
Write-Host '  Select a real network interface in the New Capture dialog.' -ForegroundColor DarkGray
Write-Host ''

Set-Location "$root\src\ui-fx"
mvn compile javafx:run

Write-Host ''
Write-Host 'Application closed. Press Enter to exit.' -ForegroundColor DarkGray
Read-Host
