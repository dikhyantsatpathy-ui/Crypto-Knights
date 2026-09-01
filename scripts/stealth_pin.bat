@echo off
REM ============================================================
REM  StealthX - ONE-CLICK PIN TO FRONT
REM  Pins the opencode/Windows PowerShell terminal to the very
REM  front so it ALWAYS stays on top of every other window.
REM  If another app steals topmost, re-run this (or use --watch).
REM  To undo: double-click stealth_unpin.bat
REM ============================================================
title StealthX Pin
cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python not found on PATH.
    pause
    exit /b 1
)

echo.
echo Choose which terminal to pin to the front:
echo   1. Windows PowerShell / opencode (auto-detect)
echo   2. Type a title fragment
echo.
set /p CHOICE=Pick (1 or 2): 

if "%CHOICE%"=="1" (
    echo Pinning the PowerShell/opencode terminal to the front...
    echo (This window will stay open - it is the keep-on-top watchdog.
    echo  Close it or press Ctrl+C to unpin.)
    python stealth.py --title "Windows PowerShell" --topmost --watch 0.5
    goto done
)
if "%CHOICE%"=="2" (
    echo.
    python stealth.py --list
    echo ----------------------------------------------
    set /p TITLE=Type a title fragment to pin: 
    if "%TITLE%"=="" exit /b 0
    python stealth.py --title "%TITLE%" --topmost --watch 0.5
    goto done
)

echo Invalid choice.
:done
echo.
echo Pinned and held. To unpin, close this window or use stealth_unpin.bat.
timeout /t 2 /nobreak >nul