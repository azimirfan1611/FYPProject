# Steam Download Monitor and PC Shutdown Script
# This script monitors Steam downloads and shuts down the PC when complete

param(
    [int]$CheckIntervalSeconds = 30,
    [int]$IdleTimeoutMinutes = 5
)

Write-Host "Steam Download Monitor Started" -ForegroundColor Green
Write-Host "Checking every $CheckIntervalSeconds seconds..."
Write-Host "Will shutdown if no downloads for $IdleTimeoutMinutes minutes"
Write-Host ""

$lastActivityTime = Get-Date
$steamPath = "$env:ProgramFiles (x86)\Steam"

if (-not (Test-Path $steamPath)) {
    $steamPath = "$env:ProgramFiles\Steam"
}

if (-not (Test-Path $steamPath)) {
    Write-Host "Steam installation not found!" -ForegroundColor Red
    exit 1
}

$downloadPath = Join-Path $steamPath "steamapps\downloading"

while ($true) {
    try {
        # Check if Steam process is running
        $steamProcess = Get-Process steam -ErrorAction SilentlyContinue
        $steamWebHelper = Get-Process steamwebhelper -ErrorAction SilentlyContinue
        
        # Check for active downloads
        $hasDownloads = $false
        if (Test-Path $downloadPath) {
            $downloadItems = Get-ChildItem $downloadPath -ErrorAction SilentlyContinue
            $hasDownloads = $downloadItems.Count -gt 0
        }
        
        # Also check Steam process memory/CPU as indicator of activity
        $isActive = $false
        if ($steamProcess -or $steamWebHelper) {
            $isActive = $true
        }
        
        $currentTime = Get-Date
        $timeSinceLastActivity = $currentTime - $lastActivityTime
        
        if ($hasDownloads -or $isActive) {
            $lastActivityTime = $currentTime
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Steam is active - Downloads: $hasDownloads, Process: $isActive"
        } else {
            $idleMinutes = [math]::Round($timeSinceLastActivity.TotalMinutes, 2)
            Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Steam idle for $idleMinutes minutes"
            
            if ($timeSinceLastActivity.TotalMinutes -ge $IdleTimeoutMinutes) {
                Write-Host "Download complete! Shutting down in 30 seconds..." -ForegroundColor Yellow
                Write-Host "Press Ctrl+C to cancel" -ForegroundColor Yellow
                Start-Sleep -Seconds 30
                
                Write-Host "Shutting down now..." -ForegroundColor Red
                Stop-Computer -Force
                exit 0
            }
        }
        
        Start-Sleep -Seconds $CheckIntervalSeconds
    }
    catch {
        Write-Host "Error: $_" -ForegroundColor Red
        Start-Sleep -Seconds $CheckIntervalSeconds
    }
}
