# Sets JAVA_HOME and updates PATH for the current PowerShell session.
# It tries common Windows JDK 21 locations; override with -JdkPath if needed.

param(
    [string]$JdkPath
)

function Set-Java {
    param([string]$PathCandidate)
    if (-not (Test-Path $PathCandidate)) { return $false }
    $env:JAVA_HOME = $PathCandidate
    $env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
    Write-Host "JAVA_HOME set to $env:JAVA_HOME"
    return $true
}

if ($JdkPath) {
    if (-not (Set-Java -PathCandidate $JdkPath)) {
        Write-Error "Provided path not found: $JdkPath"
        exit 1
    }
} else {
    $candidates = @(
        "$env:USERPROFILE\.jdks\openjdk-25",
        "$env:USERPROFILE\.jdks\openjdk-21",
        "C:\Program Files\Java\jdk-21",
        "C:\Program Files\Eclipse Adoptium\jdk-21",
        "C:\Program Files\Microsoft\jdk-21",
        "C:\Program Files\Amazon Corretto\jdk21"
    )
    $set = $false
    foreach ($c in $candidates) {
        if (Set-Java -PathCandidate $c) { $set = $true; break }
    }
    if (-not $set) {
        Write-Warning "Could not auto-detect JDK 21. Provide a path: .\\scripts\\setup-java.ps1 -JdkPath 'C:\\path\\to\\jdk-21'"
        exit 1
    }
}

java -version
mvn -v

