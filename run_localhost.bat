@echo off
title TraffNode V3 Cockpit Localhost
cd /d "%~dp0"
echo ==============================================================
echo   TRAFFNODE V3: HYBRID HARVESTER & PROXY GATEWAY COCKPIT
echo   Local Dashboard: http://127.0.0.1:8888
echo   Relay Ports Range: 10001+ (Auth: gemini:gemini)
echo ==============================================================
python -m pip install -r requirements.txt >nul 2>&1
python app.py
pause
