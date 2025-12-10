# NetPackSys JavaFX Viewer

Standalone JavaFX UI to visualize the console-generated `packet_analysis_log.txt`.

## Prerequisites

**JDK 21 is required.** If you don't have it installed:

1. Download JDK 21 from:
   - [Eclipse Adoptium](https://adoptium.net/temurin/releases/?version=21)
   - [Oracle JDK](https://www.oracle.com/java/technologies/downloads/#java21)
   - [Amazon Corretto](https://docs.aws.amazon.com/corretto/latest/corretto-21-ug/downloads-list.html)

2. Install and note the installation path (e.g., `C:\Program Files\Eclipse Adoptium\jdk-21.0.x-hotspot`)

3. Set JAVA_HOME (PowerShell):
   ```powershell
   $env:JAVA_HOME = "C:\path\to\jdk-21"
   $env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
   ```

## Build & Run

### Option 1: Using the helper script (recommended)
```powershell
cd ui-fx
PowerShell -ExecutionPolicy Bypass -File .\run-ui.ps1
```

Or if you know your JDK path:
```powershell
PowerShell -ExecutionPolicy Bypass -File .\run-ui.ps1 -JdkPath "C:\path\to\jdk-21"
```

### Option 2: Manual Maven command
```powershell
cd ui-fx
# Set JAVA_HOME first (see Prerequisites)
mvn clean compile javafx:run
```

If JavaFX SDK is not on your system path, ensure the Maven dependency downloads correctly (OpenJFX 21). You can also pass `-Dprism.order=sw` for environments without GPU acceleration.

## What it shows
- **Summary**: lines starting with `DELAY_SUMMARY`
- **Packet details**: other lines in the log
- **Delay info**: delay-related lines across layers

Use the log path field to point at any existing analyzer log file (default: `packet_analysis_log.txt` in project root).

