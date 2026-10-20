#!/bin/bash
cd "$(dirname "$0")" || exit 1
if ! command -v pwsh >/dev/null 2>&1; then
  echo "需要 PowerShell 7：brew install --cask powershell"
  read -r -n 1 -p "按任意键退出..."
  exit 1
fi
pwsh -NoProfile -File ./WalletGuard.ps1
echo
read -r -n 1 -p "按任意键退出..."
