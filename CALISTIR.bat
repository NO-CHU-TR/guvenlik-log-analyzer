@echo off
chcp 65001 >nul
title Guvenlik Log Analyzer

rem Security log needs admin rights: re-launch elevated if needed
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%~dp0"
set PYTHONUTF8=1

rem Install missing packages once
python -c "import win32evtlog, fastapi, uvicorn, sqlalchemy, matplotlib, jinja2, rich" >nul 2>&1
if %errorlevel% neq 0 (
    echo Gerekli paketler kuruluyor...
    python -m pip install pywin32 rich jinja2 matplotlib sqlalchemy fastapi "uvicorn[standard]"
)

python hepsini_calistir.py
pause
