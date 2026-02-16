# Install Git for Windows using winget, Chocolatey, or by downloading the official installer.
# Run this script from an elevated PowerShell (Run as Administrator).

function Write-Log {
    param([string]$Message)
    Write-Host "[amadioha] $Message"
}

Write-Log "Starting Git installer helper..."

# Try winget first
if (Get-Command winget -ErrorAction SilentlyContinue) {
    Write-Log "Detected winget. Installing Git via winget..."
    winget install --id Git.Git -e --source winget --accept-package-agreements --accept-source-agreements
    if ($LASTEXITCODE -eq 0) { Write-Log "Git installed via winget."; exit 0 }
    Write-Log "winget installation failed (exit code $LASTEXITCODE). Falling back..."
}

# Try Chocolatey next
if (Get-Command choco -ErrorAction SilentlyContinue) {
    Write-Log "Detected Chocolatey. Installing Git via choco..."
    choco install git -y
    if ($LASTEXITCODE -eq 0) { Write-Log "Git installed via Chocolatey."; exit 0 }
    Write-Log "choco installation failed (exit code $LASTEXITCODE). Falling back..."
}

# Fallback: download official Git for Windows installer
$installerUrl = "https://github.com/git-for-windows/git/releases/latest/download/Git-64-bit.exe"
$installerPath = Join-Path $env:TEMP "git-installer.exe"

Write-Log "Downloading Git installer from $installerUrl to $installerPath..."
try {
    Invoke-WebRequest -Uri $installerUrl -OutFile $installerPath -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Log "Failed to download installer: $_.Exception.Message"
    exit 2
}

Write-Log "Running installer silently..."
try {
    Start-Process -FilePath $installerPath -ArgumentList '/VERYSILENT','/NORESTART' -Wait -NoNewWindow
} catch {
    Write-Log "Installer execution failed: $_.Exception.Message"
    exit 3
}

# Check git availability
if (Get-Command git -ErrorAction SilentlyContinue) {
    $v = (git --version) -join ""
    Write-Log "Git installed successfully: $v"
    exit 0
} else {
    Write-Log "Git installation completed but 'git' not found in PATH. You may need to restart your terminal or log out and back in."
    Write-Log "Verify by running: git --version"
    exit 0
}
