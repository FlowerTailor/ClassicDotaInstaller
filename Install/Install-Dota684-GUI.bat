@echo off
setlocal
set GUI=%~dp0Install-Dota684-GUI.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File "%GUI%"
endlocal

