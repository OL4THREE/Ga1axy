#!/bin/bash
# Ga1axy Web Interface - 启动脚本
echo "=================================="
echo "  Ga1axy Web Interface Launcher"
echo "=================================="

# Get script directory
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR"

# Check dependencies
echo "[*] Checking dependencies..."
pip3 install -q flask pycryptodome Pillow PyJWT 2>/dev/null

# Start web interface
echo "[*] Starting Ga1axy Web Interface..."
python3 app.py
