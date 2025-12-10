# Helper script to run JavaFX UI
# Usage: .\run-ui.ps1 [path-to-jdk-21]

param(
    [string]$JdkPath = ""
)

Write-Host "=== NetPackSys JavaFX UI Launcher ===" -ForegroundColor Cyan

# Try to find JDK 21
if ([string]::IsNullOrEmpty($JdkPath)) {
    Write-Host "Searching for JDK 21..." -ForegroundColor Yellow
    
    $searchPaths = @(
        "$env:ProgramFiles\Java",
        "${env:ProgramFiles(x86)}\Java",
        "$env:ProgramFiles\Eclipse Adoptium",
        "$env:ProgramFiles\Microsoft",
        "$env:ProgramFiles\Amazon Corretto",
        "$env:ProgramFiles\BellSoft",
        "$env:ProgramFiles\Zulu",
        "$env:LOCALAPPDATA\Programs\Eclipse Adoptium",
        "$env:USERPROFILE\.jdks"
    )
    
    foreach ($base in $searchPaths) {
        if (Test-Path $base) {
            $found = Get-ChildItem $base -Directory -ErrorAction SilentlyContinue | 
                Where-Object { $_.Name -match "jdk-?21|jdk-?22|java-?21|java-?22" } | 
                Select-Object -First 1 -ExpandProperty FullName
            if ($found) {
                $JdkPath = $found
                Write-Host "Found: $JdkPath" -ForegroundColor Green
                break
            }
        }
    }
}

# Check if JDK path is valid
if ([string]::IsNullOrEmpty($JdkPath) -or -not (Test-Path "$JdkPath\bin\java.exe")) {
    Write-Host "`nERROR: JDK 21 not found!" -ForegroundColor Red
    Write-Host "Please provide JDK 21 path:" -ForegroundColor Yellow
    Write-Host "  .\run-ui.ps1 -JdkPath 'C:\path\to\jdk-21'" -ForegroundColor White
    Write-Host "`nOr set JAVA_HOME manually:" -ForegroundColor Yellow
    Write-Host "  `$env:JAVA_HOME = 'C:\path\to\jdk-21'" -ForegroundColor White
    Write-Host "  `$env:PATH = `"`$env:JAVA_HOME\bin;`$env:PATH`"" -ForegroundColor White
    exit 1
}

# Set JAVA_HOME for this session
$env:JAVA_HOME = $JdkPath
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"

Write-Host "`nJAVA_HOME set to: $env:JAVA_HOME" -ForegroundColor Green
Write-Host "Java version:" -ForegroundColor Cyan
& "$env:JAVA_HOME\bin\java.exe" -version

Write-Host "`nBuilding and launching JavaFX UI..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan

# Run Maven with JavaFX plugin
mvn clean compile javafx:run

