# NetPackSys – Getting Started (Step-by-Step)

This guide walks you through running the application and building the EXE from scratch. Use it if you are new to the project or to Java/Maven on Windows.

---

## 🚀 The Fastest Way (Highly Recommended)

If you just want to run the app with all features (Tests + Coverage + Live Capture GUI):

1. Go to the project root folder.
2. Double-click the **`run.bat`** file.
3. Click **Yes** when the Windows UAC (Administrator) prompt appears.
4. The app will:
    - Close any old instances.
    - Run all tests.
    - Open the JavaFX GUI with Administrator rights.

---

## What You Need Before Starting

| Requirement | What it is | Where to get it |
|------------|------------|------------------|
| **JDK 21 or later** | Java Development Kit | [Eclipse Temurin 21](https://adoptium.net/temurin/releases/?version=21) or [Oracle JDK 21](https://www.oracle.com/java/technologies/downloads/#java21) |
| **Maven** | Build tool | [Apache Maven](https://maven.apache.org/download.cgi) – extract and add `bin` to PATH |
| **PowerShell** | Command line | Built into Windows (Windows Key → type `PowerShell`) |

Optional for **live packet capture**:

- **Npcap** (Windows): [https://npcap.com](https://npcap.com) – install so the app can capture real packets.
- **Administrator Privileges**: Required for live capture (The `run.bat` handles this automatically).
- **Smart Discovery**: The GUI now features 🔥 **Smart Traffic Discovery** — it scans your network cards and highlights the one currently being used for browsing to help you start successful captures instantly.

---

## Part 1: Set Up Java (One-Time)

1. Install JDK 21 (or 22+) using the installer from the link above.
2. Note the install path, for example:
   - `C:\Program Files\Eclipse Adoptium\jdk-21.x.x-hotspot`
   - or `C:\Users\YourName\.jdks\openjdk-21`
3. Open **PowerShell** (Windows Key → type `PowerShell` → Enter).
4. Set Java for this session (replace the path with your actual JDK path):
   ```powershell
   $env:JAVA_HOME = "C:\Program Files\Eclipse Adoptium\jdk-21.0.1.12-hotspot"
   $env:PATH = "$env:JAVA_HOME\bin;$env:PATH"
   ```
5. Check that Java works:
   ```powershell
   java -version
   ```
   You should see something like `openjdk version "21.x.x"`.
6. Check Maven (if you installed it):
   ```powershell
   mvn -version
   ```

---

## Part 2: Open the Project Folder

1. In PowerShell, go to the folder where you have the NetPackSys project, for example:
   ```powershell
   cd C:\Users\YourName\workstation\shaleen\iit\oop\NetPackSys
   ```
2. Replace the path above with your real path. You must be in the folder that contains the file `pom.xml` (the project root).

---

## Part 3: Run the Tests

1. Make sure you are in the **project root** (the folder with `pom.xml`).
2. Set Java if you have not already (see Part 1, step 4).
3. Run:
   ```powershell
   mvn clean test
   ```
4. Wait until it finishes. At the end you should see **BUILD SUCCESS** and a line like **Tests run: 44, Failures: 0**.
5. If you see **JAVA_HOME is not defined**, go back to Part 1 and set `JAVA_HOME` and `PATH` again.

---

## Part 4: Run the Console App (Core)

1. Stay in the **project root** (folder with `pom.xml`).
2. Build the JAR:
   ```powershell
   mvn clean package -DskipTests
   ```
3. Run the console application:
   ```powershell
   java -jar target\NetPackSys-1.0-SNAPSHOT-jar-with-dependencies.jar
   ```
4. Follow the prompts: choose **sim** for simulation, enter duration (e.g. `10`), and protocols (e.g. `ALL`). The app will run and write to `packet_analysis_log.txt`.

---

## Part 5: Run the JavaFX App (GUI) with Maven

1. Install the core into your local Maven repo (from **project root**):
   ```powershell
   mvn clean install -DskipTests
   ```
2. Go into the UI module folder:
   ```powershell
   cd src\ui-fx
   ```
3. Start the GUI:
   ```powershell
   mvn clean javafx:run
   ```
4. The NetPackSys window opens. You can:
   - Click **New Capture** → choose **Simulation mode** → set duration and protocols → **Start capture** (no admin needed), or
   - Choose a real interface and **Start capture** (then the app must be run as Administrator for live capture to work).

---

## Part 6: Run the JavaFX App Using Scripts (Easier)

From the **project root** (the folder with `pom.xml`):

1. Allow the setup script to run (one time per session if your system blocks scripts):
   ```powershell
   Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
   ```
2. Set Java and PATH using the project script (use your real JDK path if needed):
   ```powershell
   .\scripts\setup-java.ps1 -JdkPath "C:\Program Files\Eclipse Adoptium\jdk-21.0.1.12-hotspot"
   ```
   If Java is already in a standard location (e.g. `%USERPROFILE%\.jdks\openjdk-21`), you can run:
   ```powershell
   .\scripts\setup-java.ps1
   ```
3. Run the GUI:
   ```powershell
   .\scripts\run-ui.ps1
   ```
4. To run the GUI **as Administrator** (for live capture) in one go:
   ```powershell
   .\scripts\run-ui.ps1 -RunAsAdmin
   ```
   A UAC window will appear; click **Yes**. A new window will open and start the app with admin rights.

---

## Part 7: Build and Run the EXE (Always Asks for Admin)

The EXE will always prompt for Administrator when you double-click it, so you do not need to right-click “Run as administrator”.

### Build the EXE

1. Open PowerShell and go to the **project root** (folder with `pom.xml`).
2. Set Java (see Part 1, step 4), or run:
   ```powershell
   .\scripts\setup-java.ps1 -JdkPath "C:\path\to\your\jdk-21"
   ```
3. Build the EXE:
   ```powershell
   .\scripts\build-exe.ps1
   ```
4. Wait until the build finishes. You should see a message like “Done. EXE and lib folder” with two paths.

### Where the EXE Is

- **EXE file:**  
  `src\ui-fx\target\dist\NetPackSys.exe`
- **Required JARs (must stay next to the EXE):**  
  `src\ui-fx\target\dist\lib\`  
  Do **not** move the EXE without the `lib` folder.

### Run the EXE

1. Open File Explorer and go to:
   ```
   YourProjectFolder\src\ui-fx\target\dist
   ```
2. (Optional) Copy the **entire `dist` folder** (including the `lib` folder inside it) to Desktop or any other place. You must keep `NetPackSys.exe` and the `lib` folder in the same folder.
3. Double-click **NetPackSys.exe**.
4. When Windows shows the **User Account Control** dialog (“Do you want to allow this app to make changes?”), click **Yes**.
5. The NetPackSys window opens with Administrator rights; live capture will work.

### If the EXE Does Not Start

- Make sure the **lib** folder is in the same folder as **NetPackSys.exe**.
- Make sure **JDK 21+** is installed and that `java -version` works in a new PowerShell window (the EXE uses the system Java).
- If you see a “Java not found” message, install JDK 21 and try again.

---

## Quick Reference

| What you want to do | Where to be | Command |
|--------------------|-------------|---------|
| **Run everything (tests + coverage + GUI)** | Project root | `.\scripts\run-all.ps1` |
| Run tests | Project root | `mvn clean test` |
| Run console app | Project root | `mvn package -DskipTests` then `java -jar target\NetPackSys-1.0-SNAPSHOT-jar-with-dependencies.jar` |
| Run GUI (Maven) | Project root, then `src\ui-fx` | `mvn install -DskipTests` then `cd src\ui-fx` then `mvn javafx:run` |
| Run GUI (script) | Project root | `.\scripts\run-ui.ps1` |
| Run GUI as Admin (script) | Project root | `.\scripts\run-ui.ps1 -RunAsAdmin` |
| Build EXE | Project root | `.\scripts\build-exe.ps1` |
| Run EXE | Anywhere (copy `dist` folder first) | Double-click `NetPackSys.exe` |

---

## Troubleshooting

- **“JAVA_HOME is not defined”**  
  Set it (Part 1, step 4) or run `.\scripts\setup-java.ps1 -JdkPath "C:\path\to\jdk-21"`.

- **“Running scripts is disabled”**  
  Run once:  
  `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`  
  Or run the script with:  
  `PowerShell -ExecutionPolicy Bypass -File .\scripts\run-ui.ps1`

- **GUI “hangs” when you start live capture**  
  Live capture needs Administrator rights. Use **Simulation mode**, or run the app as Administrator (e.g. `.\scripts\run-ui.ps1 -RunAsAdmin`) or use the EXE and click **Yes** on the UAC prompt.

- **EXE does not start or says Java not found**  
  Install JDK 21 and ensure `java -version` works. Keep the `lib` folder next to the EXE.

For more on the UI (features, architecture), see **src/ui-fx/README.md**. For project overview and design, see **README.md**.
