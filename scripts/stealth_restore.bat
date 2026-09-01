@echo off
REM ============================================================
REM  StealthX - ONE-CLICK RESTORE
REM  Brings back every console window that was hidden.
REM  Double-click this file ANY time to claw back your terminal.
REM  It opens its own window and closes after restoring.
REM ============================================================
title StealthX Restore
cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python not found on PATH.
    echo Try: python3 or py, or install Python.
    pause
    exit /b 1
)

echo Restoring hidden console windows...
python stealth.py --unhide-all

echo.
echo Done. All console windows restored.
timeout /t 2 /nobreak >nul