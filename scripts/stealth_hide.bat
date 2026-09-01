@echo off
REM ============================================================
REM  StealthX - ONE-CLICK HIDE
REM  Hides a window by the title text you type (or use --self
REM  to hide the console that launches this).
REM
REM  IMPORTANT: this hides the taskbar button too. To get the
REM  window back, double-click stealth_restore.bat
REM  (or press your --hotkey if one is running).
REM ============================================================
title StealthX Hide
cd /d "%~dp0"

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python not found on PATH.
    pause
    exit /b 1
)

echo.
echo StealthX Hide - list of currently visible windows:
echo ----------------------------------------------
python stealth.py --list
echo ----------------------------------------------
echo.
set /p TITLE=Type a fragment of the window title to hide (or type SELFPARENT to hide this terminal): 
if "%TITLE%"=="" exit /b 0

if /I "%TITLE%"=="SELFPARENT" (
    echo Hiding this terminal's console...
    python stealth.py --self
    goto done
)

echo Hiding windows with title containing: %TITLE%
python stealth.py --title "%TITLE%" --capture --hide
echo.
echo Done. To restore: double-click stealth_restore.bat
:done
timeout /t 2 /nobreak >nul