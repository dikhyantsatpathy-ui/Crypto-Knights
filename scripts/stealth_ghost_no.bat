@echo off
REM ============================================================
REM  StealthX - ONE-CLICK GHOST OFF (restore taskbar button)
REM  Removes the toolwindow flag and drops the always-on-top,
REM  giving your terminal back its normal taskbar button.
REM ============================================================
title StealthX Unghost
cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python not found on PATH.
    pause
    exit /b 1
)

echo Restoring normal taskbar button for the terminal...
python stealth.py --title "Windows PowerShell" --unghost

echo.
echo Done. Taskbar button restored, always-on-top removed.
timeout /t 2 /nobreak >nul