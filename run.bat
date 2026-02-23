@echo off
REM NetPackSys Launcher
REM This batch file runs the PowerShell script that executes tests, coverage, and the GUI.

SET SCRIPTPATH=%~dp0scripts\run-all.ps1

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%SCRIPTPATH%"

if %ERRORLEVEL% neq 0 (
    echo.
    echo [ERROR] The application exited with code %ERRORLEVEL%.
    pause
)
