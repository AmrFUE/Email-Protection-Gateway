# EPG GitHub Sync Script
# Run this script to automatically push your latest changes to GitHub.

# Check if git is installed
if (-not (Get-Command "git" -ErrorAction SilentlyContinue)) {
    Write-Host "Git is not installed or not in your PATH. Please install Git for Windows." -ForegroundColor Red
    Pause
    Exit
}

$repoUrl = git config --get remote.origin.url
if (-not $repoUrl) {
    Write-Host "Your Git repository is not connected to GitHub yet!" -ForegroundColor Yellow
    Write-Host "Please create a new repository on GitHub and run the following commands:" -ForegroundColor Yellow
    Write-Host "git remote add origin https://github.com/AmrFUE/Email-Protection-Gateway.git" -ForegroundColor Cyan
    Write-Host "git branch -M main" -ForegroundColor Cyan
    Write-Host "git push -u origin main" -ForegroundColor Cyan
    Pause
    Exit
}

Write-Host "Scanning for changes..." -ForegroundColor Cyan

# Stage all changes
git add .

# Check if there are any changes to commit
$status = git status --porcelain
if ([string]::IsNullOrWhiteSpace($status)) {
    Write-Host "No changes to commit. Your repository is up to date!" -ForegroundColor Green
    Pause
    Exit
}

# Prompt for a commit message
$commitMessage = Read-Host "Enter a commit message (or press Enter for 'Auto-update')"
if ([string]::IsNullOrWhiteSpace($commitMessage)) {
    $commitMessage = "Auto-update $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
}

# Commit and push
Write-Host "Committing changes..." -ForegroundColor Cyan
git commit -m $commitMessage

Write-Host "Pushing to GitHub..." -ForegroundColor Cyan
git push origin main

if ($LASTEXITCODE -eq 0) {
    Write-Host "Successfully synced with GitHub!" -ForegroundColor Green
} else {
    Write-Host "Failed to push to GitHub. Check the error above." -ForegroundColor Red
}

Pause
