@echo off
chcp 65001 >nul
title WalletGuard - Binance Agentic Wallet exposure self-check
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0WalletGuard.ps1"
echo.
pause