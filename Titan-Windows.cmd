@echo off
setlocal
cd /d "%~dp0"

set "TITAN_PYTHON=%~dp0.venv-windows\Scripts\pythonw.exe"
if not exist "%TITAN_PYTHON%" (
    echo Titan's Windows desktop environment is not installed.
    echo Expected: %TITAN_PYTHON%
    echo.
    echo Re-run the Windows desktop setup, then try again.
    pause
    exit /b 1
)

start "Titan Forensic Workbench" "%TITAN_PYTHON%" -m titan_decoder.launcher
