@echo off
rem 启动 FlutifyPS（Windows）
cd /d "%~dp0.."
node server.js %*
