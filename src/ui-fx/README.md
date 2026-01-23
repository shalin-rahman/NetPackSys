# Packet Log Viewer (UI-FX)

A JavaFX-based Graphical User Interface for the **NetPackSys** Network Analyzer. This application allows users to capture live network traffic, view real-time packet statistics, and analyze nodal delays in a structured tabular format.

## Features

-   **Active Network Capture**: 
    -   Capture live packets from any available network interface.
    -   "Simulation Mode" for testing without network hardware.
    -   Configurable **Duration**, **Protocols** (e.g., TCP, HTTP, TLS), and **Output File**.
-   **Structured Table View**: 
    -   Displays packet summaries (Frame No, Time, Source/Dest IP, Protocol, Length, Info, Delay) in a sortable table.
-   **Detailed Analysis**:
    -   Select any packet to view its full raw content and detailed breakdown.
-   **Log Management**:
    -   Automatically loads the latest capture.
    -   "View Log File" button to open the raw text log in your system editor.

## Requirements

-   **Java 21+**
-   **Maven**
-   **Npcap** (for Windows) or **libpcap** (for Linux/macOS) installed for live capture.
-   **Administrator Privileges** are required for live network capture.

## Running the Application

### Prerequisite: Install the Core

This UI depends on the **NetPackSys** core JAR. You **must** build and install it from the **project root** first:

```powershell
cd c:\Users\Admin\Desktop\NetPackSys
mvn clean install -DskipTests
```

Then `cd src\ui-fx` and run the commands below.

### Option 1: Live Capture (Run as Administrator)

To capture packets from a real network interface, you **must** run the app as **Administrator**. Two ways:

#### A. Helper script (elevates automatically)

From `src\ui-fx`:

```powershell
.\run_admin.ps1
```

- A **UAC prompt** will ask “Do you want to allow this app to make changes?” → click **Yes**.
- A new elevated PowerShell window opens and starts the UI. Use that window; you can ignore the original one.

**If the script fails** (e.g. “mvn not found” or “java not found”): when run as Admin, PATH can differ. Edit `run_admin.ps1` and set `JAVA_HOME` to your JDK folder (e.g. `C:\Program Files\Java\jdk-21`) and ensure Maven’s `bin` is on `PATH`, then run the script again.

#### B. Manual “Run as Administrator”

1. Close any existing PowerShell/CMD.
2. **Right‑click** **Windows PowerShell** or **Command Prompt** → **Run as administrator**.
3. In the new window:
   ```powershell
   cd c:\Users\Admin\Desktop\NetPackSys
   mvn clean install -DskipTests
   cd src\ui-fx
   mvn clean javafx:run
   ```
4. The UI runs with admin rights; live capture will work.

### Option 2: Maven (Development/Simulation)
If you only need to run "Simulation Mode" or view existing logs:

```powershell
mvn clean javafx:run
```

## Architecture

Refectored using **SOLID** principles and the **Model-View-Presenter (MVP)** pattern:
-   **Model**: `PacketRecord` (Immutable data carrier).
-   **View**: `PacketLogViewer` (JavaFX UI, passive).
-   **Presenter**: `LogPresenter` (Orchestrates logic).
-   **Service**: `FileLogFileService` (File I/O).
-   **Processor**: `TableLogProcessor`, `DetailLogProcessor` (Parsing logic).
