@echo off
REM ============================================================
REM  StealthX - ONE-CLICK UNPIN
REM  Removes the always-on-top pin from the opencode terminal.
REM ============================================================
title StealthX Unpin
cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python not found on PATH.
    pause
    exit /b 1
)

echo Unpinning the PowerShell/opencode terminal (removing topmost)...
python stealth.py --title "Windows PowerShell" --unpin

echo.
echo Done. Terminal no longer pinned on top.
timeout /t 2 /nobreak >nul