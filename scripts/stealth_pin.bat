@echo off
REM ============================================================
REM  StealthX - ONE-CLICK GHOST PIN
REM  Makes the terminal WINDOWED, ALWAYS-ON-TOP, and hidden from
REM  the taskbar (no button, no alt-tab) -- exactly the clean
REM  "pyw" behaviour. It stays visible on screen at all times,
REM  never flashes or minimizes, and floating above everything.
REM  To undo: double-click ghost_off.bat
REM ============================================================
title StealthX Ghost Pin
cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python not found on PATH.
    pause
    exit /b 1
)

echo.
echo Terminal mode:
echo   1. GHOST - windowed + always-on-top + hidden from taskbar (recommended)
echo   2. PIN   - always-on-top only (keeps taskbar button, runs watchdog)
echo.
set /p CHOICE=Pick (1 or 2): 

if "%CHOICE%"=="2" (
    python stealth.py --title "Windows PowerShell" --topmost --watch 0.5
    goto done
)

echo Ghosting the PowerShell/opencode terminal...
python stealth.py --title "Windows PowerShell" --ghost

echo.
echo GHOSTED - it is windowed, floating on top, and hidden from the taskbar.
echo To restore the normal taskbar button: double-click stealth_ghost_no.bat
timeout /t 2 /nobreak >nul