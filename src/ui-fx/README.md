# Packet Log Viewer (UI-FX)

JavaFX GUI for the **NetPackSys** network analyzer: capture live traffic (or use Simulation), view packet tables, and inspect delay analysis.

**First time?** Use the project’s step-by-step guide: **[GETTING-STARTED.md](../../GETTING-STARTED.md)** (from project root).

## Features

-   **Smart Network Capture**: 
    -   🔥 **Smart Discovery**: Automatically scans all active network interfaces for live traffic (packets/sec) and prioritizes the one currently being used.
    -   **Color-Coded Status**: Active interfaces are shown in bold green; inactive ones in gray.
    -   "Simulation Mode" for testing without network hardware.
    -   Configurable **Duration**, **Protocols** (CSV or "ALL"), and **Output File**.
-   **Structured Table View**: 
    -   Displays unified packet summaries in a clean, multi-column grid.
    -   **Enhanced Nodal Delay Column**: Instead of showing 0, it confirms processing with labels like `Processed [Pkt #X]`.
-   **Detailed Analysis**:
    -   Select any packet to view its full raw content and detailed breakdown.
-   **Log Management**:
    -   Automatically loads the latest capture upon completion.
    -   "View Log File" button to open the raw text log in your system editor.

## Requirements

-   **Java 21+**
-   **Maven**
-   **Npcap** (for Windows) or **libpcap** (for Linux/macOS) installed for live capture.
-   **Administrator Privileges** are required for live network capture.

## Running the Application

### Step-by-step (from project root)

1. Open PowerShell and go to the project root (folder with `pom.xml`).
2. Set Java: `.\scripts\setup-java.ps1 -JdkPath "C:\path\to\jdk-21"`
3. Install core: `mvn clean install -DskipTests`
4. Go to UI folder: `cd src\ui-fx`
5. Start GUI: `mvn clean javafx:run`

### Option A: Script from project root

From **project root**: `.\scripts\run-ui.ps1`  
For **live capture** (as Administrator): `.\scripts\run-ui.ps1 -RunAsAdmin` (UAC → Yes).

- A **UAC prompt** will ask “Do you want to allow this app to make changes?” → click **Yes**.
- A new elevated PowerShell window opens and starts the UI. Use that window; you can ignore the original one.

**If the script fails** (e.g. “mvn not found” or “java not found”): when run as Admin, PATH can differ. Edit `scripts\run-ui.ps1` and set `JAVA_HOME` to your JDK folder (e.g. `C:\Program Files\Java\jdk-21`) and ensure Maven’s `bin` is on `PATH`, then run the script again.

### Option B: Run as Administrator manually

1. Right‑click **PowerShell** → **Run as administrator**.
2. In the new window: cd to project root, then run `mvn install -DskipTests`, then `cd src\ui-fx`, then `mvn javafx:run`.

### Option C: Run the EXE (always asks for Administrator)

You can build a **NetPackSys.exe** that **always prompts for Administrator** when double‑clicked (UAC). No need to right‑click “Run as administrator”.

From the **project root** (with `JAVA_HOME` set, e.g. via `scripts\setup-java.ps1`):

```powershell
.\scripts\build-exe.ps1
```

Output:

- `src\ui-fx\target\dist\NetPackSys.exe` — the launcher (run this)
- `src\ui-fx\target\dist\lib\` — required JARs (must stay next to the exe)

**To use:** Copy the whole **dist** folder (exe + **lib** folder) to any location. Double‑click **NetPackSys.exe**; Windows will show the UAC prompt, then the app starts with admin rights so live capture works.

## Architecture

Refectored using **SOLID** principles and the **Model-View-Presenter (MVP)** pattern:
-   **Model**: `PacketRecord` (Immutable data carrier).
-   **View**: `PacketLogViewer` (JavaFX UI, passive).
-   **Presenter**: `LogPresenter` (Orchestrates logic).
-   **Service**: `FileLogFileService` (File I/O).
-   **Processor**: `TableLogProcessor`, `DetailLogProcessor` (Parsing logic).
