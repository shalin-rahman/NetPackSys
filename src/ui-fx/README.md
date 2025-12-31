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

### Option 1: Live Capture (Recommended)
To capture packets from a real network interface, you must run the application as Administrator. A helper script is provided:

```powershell
.\run_admin.ps1
```
*Accept the UAC prompt to launch the analyzer with elevated privileges.*

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
