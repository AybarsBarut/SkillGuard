# SkillGuard One-Line Installer for Windows (PowerShell)
# Usage: irm https://raw.githubusercontent.com/4rchura/skillguard/main/install.ps1 | iex

$ErrorActionPreference = "Stop"

Write-Host "`n🛡️  SkillGuard Kurulumu Başlatılıyor... / Initializing SkillGuard Installation..." -ForegroundColor Cyan

# 1. Check Python
try {
    $pyVer = python --version 2>&1
    Write-Host "✅ Python tespit edildi: $pyVer" -ForegroundColor Green
} catch {
    Write-Host "❌ Python 3.10+ bulunamadı! Lütfen Python'ı yükleyin ve PATH'e ekleyin." -ForegroundColor Red
    exit 1
}

# 2. Determine installation target
$targetDir = "$PWD/.agents/skills/skillguard"
if (Test-Path "SKILL.md") {
    # Running from inside the cloned repo
    $targetDir = $PWD
} else {
    Write-Host "📁 SkillGuard yerel ortama kopyalanıyor: $targetDir" -ForegroundColor Yellow
    New-Item -ItemType Directory -Force -Path $targetDir | Out-Null
    
    # Clone or fetch repo
    $repoUrl = "https://github.com/4rchura/skillguard.git"
    git clone --depth 1 $repoUrl $targetDir
}

# 3. Run hook installer
Write-Host "⚙️  Git ve Agent yaşam döngüsü hook'ları kuruluyor..." -ForegroundColor Yellow
python "$targetDir/scripts/install_hooks.py" --dir $PWD

# 4. Success message
Write-Host "`n🎉 SkillGuard Başarıyla Kuruldu!" -ForegroundColor Green
Write-Host "   - Git Pre-Commit/Push Hook'ları: Aktif" -ForegroundColor Gray
Write-Host "   - Antigravity & Agent Hook'ları: Aktif (.agents/hooks.json)" -ForegroundColor Gray
Write-Host "   - Güvenlik Raporu Üretmek İçin: python scripts/report.py`n" -ForegroundColor Cyan
