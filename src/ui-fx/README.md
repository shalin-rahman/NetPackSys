# Packet Log Viewer

JavaFX-based GUI for viewing NetPackSys packet analysis logs.

## Running the Viewer

```powershell
cd src\ui-fx
$env:JAVA_HOME = "C:\Users\HabiburRahmanShalin\.jdks\openjdk-25.0.1"
$env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
mvn javafx:run
```

## What it does

Displays packet analysis logs from `packet_analysis_log.txt` in three sections:
- Summary lines (DELAY_SUMMARY)
- Packet details
- Delay information
