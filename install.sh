#!/usr/bin/env bash
# SkillGuard One-Line Installer for Linux / macOS
# Usage: curl -fsSL https://raw.githubusercontent.com/4rchura/skillguard/main/install.sh | bash

set -e

echo ""
echo "[SKILLGUARD] Initializing SkillGuard Installation..."

# 1. Check Python
if ! command -v python3 &> /dev/null && ! command -v python &> /dev/null; then
    echo "[ERROR] Python 3.10+ not found! Please install Python 3.10+ and add it to your PATH."
    exit 1
fi

PYTHON_CMD="python3"
if ! command -v python3 &> /dev/null; then
    PYTHON_CMD="python"
fi

PY_VER=$($PYTHON_CMD --version)
echo "[OK] Python detected: $PY_VER"

# 2. Determine target directory
TARGET_DIR="$PWD/.agents/skills/skillguard"
if [ -f "SKILL.md" ]; then
    TARGET_DIR="$PWD"
else
    echo "[INFO] Cloning SkillGuard into: $TARGET_DIR"
    mkdir -p "$TARGET_DIR"
    git clone --depth 1 https://github.com/4rchura/skillguard.git "$TARGET_DIR"
fi

# 3. Run hook installer
echo "[INFO] Installing Git and Agent lifecycle hooks..."
$PYTHON_CMD "$TARGET_DIR/scripts/install_hooks.py" --dir "$PWD"

echo ""
echo "[OK] SkillGuard Successfully Installed!"
echo "   - Git Pre-Commit & Pre-Push Hooks: Active"
echo "   - Agent Hooks: Configured (.agents/hooks.json)"
echo "   - Run Security Audit: python scripts/report.py"
echo ""
