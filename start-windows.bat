@echo off
setlocal enabledelayedexpansion
set "SCRIPT_DIR=%~dp0"
if "%SCRIPT_DIR:~0,2%"=="\\" (
  echo.
  echo This folder is on a network path, not a local drive:
  echo    !SCRIPT_DIR!
  echo.
  echo Windows cmd.exe cannot run from a \\server\share path - this shows up
  echo most often when running Windows in Parallels on a Mac from \\Mac\Home.
  echo Copy this whole folder to a local drive first ^(e.g. C:\NetworkAutomationStudio^)
  echo and run start-windows.bat again from that copy.
  echo.
  pause
  exit /b 1
)
cd /d "!SCRIPT_DIR!"
if not exist .venv (
  python -m venv .venv
)
call .venv\Scripts\activate.bat
python -m pip install -r requirements.txt
python run.py
pause
