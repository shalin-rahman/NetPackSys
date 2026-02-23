# Scripts

Helper scripts for NetPackSys. Run them from the **project root** (the folder that contains `pom.xml`).

| Script | Purpose |
|--------|--------|
| **run-all.ps1** | **Main Entry Point**. Automatically elevates to Admin, closes old instances, runs all tests with JaCoCo coverage, and launches the GUI. |
| **setup-java.ps1** | Sets `JAVA_HOME` and `PATH` for the current session. |
| **run-tests.ps1** | Runs core tests, installs core, then runs UI-FX tests. |
| **run-ui.ps1** | Builds and runs the JavaFX app. Use `-RunAsAdmin` for live capture. |
| **build-exe.ps1** | Builds `NetPackSys.exe` (self-elevating). Output: `src\ui-fx\target\dist\`. |

If PowerShell blocks scripts, run once:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

Or run a script with:

```powershell
PowerShell -ExecutionPolicy Bypass -File .\scripts\run-ui.ps1
```

For full step-by-step instructions, see **[GETTING-STARTED.md](../GETTING-STARTED.md)**.
