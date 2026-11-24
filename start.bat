@echo off
title Wedding Invitation Server
echo ===================================================
echo   Starting Wedding Invitation Server...
echo ===================================================
cd /d "%~dp0"
if exist "server.js" (
    start http://localhost:3000
    node server.js
) else if exist "..\server.js" (
    start http://localhost:3000
    node ..\server.js
) else (
    echo [ERROR] server.js not found!
    pause
)
