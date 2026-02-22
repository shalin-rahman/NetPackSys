# Scripts

Helper scripts for NetPackSys. Run them from the **project root** (the folder that contains `pom.xml`).

| Script | Purpose |
|--------|--------|
| **setup-java.ps1** | Sets `JAVA_HOME` and `PATH` for the current session. Use once before running Maven. Optional: `-JdkPath "C:\path\to\jdk-21"`. |
| **run-tests.ps1** | Runs core tests, installs core, then runs UI-FX tests. Optional: `-JdkPath "C:\path\to\jdk-21"`. |
| **run-ui.ps1** | Builds and runs the JavaFX app. Use `-RunAsAdmin` for live capture. Optional: `-JdkPath "C:\path\to\jdk-21"`. |
| **build-exe.ps1** | Builds `NetPackSys.exe` (always asks for Administrator). Output: `src\ui-fx\target\dist\`. Optional: `-JdkPath "C:\path\to\jdk-21"`. |

If PowerShell blocks scripts, run once:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Or run a script with:

```powershell
PowerShell -ExecutionPolicy Bypass -File .\scripts\run-ui.ps1
```

For full step-by-step instructions, see **[GETTING-STARTED.md](../GETTING-STARTED.md)**.
