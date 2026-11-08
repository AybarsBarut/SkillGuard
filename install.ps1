# SkillGuard One-Line Installer for Windows (PowerShell)
# Usage: irm https://raw.githubusercontent.com/4rchura/skillguard/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

Write-Host "`n[SKILLGUARD] Initializing SkillGuard Installation..." -ForegroundColor Cyan

# 1. Check Python
try {
    $pyVer = python --version 2>&1
    Write-Host "[OK] Python detected: $pyVer" -ForegroundColor Green
} catch {
    Write-Host "[ERROR] Python 3.10+ not found! Please install Python and add it to PATH." -ForegroundColor Red
    exit 1
}

# 2. Determine installation target
$targetDir = "$PWD/.agents/skills/skillguard"
if (Test-Path "SKILL.md") {
    # Running from inside the cloned repo
    $targetDir = $PWD
} else {
    Write-Host "[INFO] Copying SkillGuard to local environment: $targetDir" -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
    
    # Clone or fetch repo
    $repoUrl = "https://github.com/4rchura/skillguard.git"
    git clone --depth 1 $repoUrl $targetDir
}

# 3. Run hook installer
Write-Host "[INFO] Installing Git and Agent lifecycle hooks..." -ForegroundColor Yellow
python "$targetDir/scripts/install_hooks.py" --dir $PWD

# 4. Success message
Write-Host "`n[OK] SkillGuard Successfully Installed!" -ForegroundColor Green
Write-Host "   - Git Pre-Commit/Push Hooks: Active" -ForegroundColor Gray
Write-Host "   - Antigravity & Agent Hooks: Active (.agents/hooks.json)" -ForegroundColor Gray
Write-Host "   - To Generate Security Report: python scripts/report.py`n" -ForegroundColor Cyan
