@echo off
setlocal
set SCRIPT=%~dp0Install-Dota684.ps1
REM Elevate to admin and run with friendly defaults for true 1-click
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process PowerShell -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -File \"%SCRIPT%\" -InstallPrereqs -BlockDota2Site -OpenQueue'"
endlocal

