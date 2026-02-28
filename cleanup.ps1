# ============================================
# WINDOWS DEEP CLEANUP SCRIPT
# Run as Administrator
# ============================================

Write-Host "=== STARTING DEEP CLEANUP ===" -ForegroundColor Red

# 1. WINDOWS TEMP FILES ---
Write-Host "[1/15] Cleaning Temp Files..." -ForegroundColor Yellow
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue

# 2. PREFETCH (Program execution history) ---
Write-Host "[2/15] Cleaning Prefetch..." -ForegroundColor Yellow
Remove-Item -Path "C:\Windows\Prefetch\*" -Force -ErrorAction SilentlyContinue

# 3. WINDOWS EVENT LOGS ---
Write-Host "[3/15] Clearing ALL Event Logs..." -ForegroundColor Yellow
Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | ForEach-Object {
    try {
        [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.ClearLog($_.LogName)
    } catch {}
}
wevtutil el | ForEach-Object { wevtutil cl "$_" 2>$null }

# 4. RECENT FILES / JUMP LISTS ---
Write-Host "[4/15] Cleaning Recent Files & Jump Lists..." -ForegroundColor Yellow
Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations\*" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:APPDATA\Microsoft\Windows\Recent\CustomDestinations\*" -Force -ErrorAction SilentlyContinue

# 5. THUMBNAIL CACHE ---
Write-Host "[5/15] Cleaning Thumbnail Cache..." -ForegroundColor Yellow
Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\thumbcache_*.db" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Explorer\iconcache_*.db" -Force -ErrorAction SilentlyContinue

# 6. WINDOWS SEARCH INDEX ---
Write-Host "[6/15] Clearing Search Index..." -ForegroundColor Yellow
Remove-Item -Path "C:\ProgramData\Microsoft\Search\Data\*" -Recurse -Force -ErrorAction SilentlyContinue

# 7. DNS CACHE ---
Write-Host "[7/15] Flushing DNS Cache..." -ForegroundColor Yellow
ipconfig /flushdns | Out-Null
Clear-DnsClientCache

# 8. ARP / NETWORK CACHE ---
Write-Host "[8/15] Clearing Network Caches..." -ForegroundColor Yellow
arp -d * 2>$null
nbtstat -R 2>$null
netsh interface ip delete arpcache 2>$null

# 9. WINDOWS ERROR REPORTING ---
Write-Host "[9/15] Cleaning Error Reports..." -ForegroundColor Yellow
Remove-Item -Path "C:\ProgramData\Microsoft\Windows\WER\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\WER\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Users\*\AppData\Local\Microsoft\Windows\WER\*" -Recurse -Force -ErrorAction SilentlyContinue

# 10. CRASH DUMPS ---
Write-Host "[10/15] Cleaning Crash Dumps..." -ForegroundColor Yellow
Remove-Item -Path "C:\Windows\Minidump\*" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\MEMORY.DMP" -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LOCALAPPDATA\CrashDumps\*" -Force -ErrorAction SilentlyContinue

# 11. WINDOWS UPDATE CACHE ---
Write-Host "[11/15] Cleaning Update Cache..." -ForegroundColor Yellow
Stop-Service wuauserv -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\SoftwareDistribution\Download\*" -Recurse -Force -ErrorAction SilentlyContinue
Start-Service wuauserv -ErrorAction SilentlyContinue

# 12. NTFS / USN JOURNAL (File operation history) ---
Write-Host "[12/15] Clearing USN Journal..." -ForegroundColor Yellow
fsutil usn deletejournal /d C: 2>$null
fsutil usn createjournal m=1000 a=100 C: 2>$null

# 13. REGISTRY - RECENT DOCS / TYPED PATHS / RUN HISTORY ---
Write-Host "[13/15] Cleaning Registry Traces..." -ForegroundColor Yellow

# Recent documents
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs" -Name * -Force -ErrorAction SilentlyContinue

# Typed paths in Explorer
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths" -Name * -Force -ErrorAction SilentlyContinue

# Run dialog history
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name * -Force -ErrorAction SilentlyContinue

# Search history
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery" -Name * -Force -ErrorAction SilentlyContinue

# ComDlg32 (Open/Save dialog history)
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU" -Recurse -Force -ErrorAction SilentlyContinue

# UserAssist (tracks every program launched - ROT13 encoded)
Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*" -Recurse -Force -ErrorAction SilentlyContinue

#  14. BROWSER CACHES (All Major Browsers) ---
Write-Host "[14/15] Cleaning Browser Data..." -ForegroundColor Yellow

# Chrome
Remove-Item -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Code Cache\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\GPUCache\*" -Recurse -Force -ErrorAction SilentlyContinue

# Firefox
Remove-Item -Path "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*\cache2\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles\*\startupCache\*" -Recurse -Force -ErrorAction SilentlyContinue

# Edge
Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Code Cache\*" -Recurse -Force -ErrorAction SilentlyContinue

#  15. ADDITIONAL FORENSIC TRACES ---
Write-Host "[15/15] Cleaning Forensic Traces..." -ForegroundColor Yellow

# BAM (Background Activity Monitor - tracks executables)
# Remove-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\*" -Recurse -Force -ErrorAction SilentlyContinue

# SRUM (System Resource Usage Monitor)
# Stop-Service DPS -Force -ErrorAction SilentlyContinue
# Remove-Item -Path "C:\Windows\System32\sru\SRUDB.dat" -Force -ErrorAction SilentlyContinue
# Start-Service DPS -ErrorAction SilentlyContinue

# Compatibility Assistant Store
Remove-Item -Path "C:\Windows\appcompat\Programs\*" -Force -ErrorAction SilentlyContinue

# Cortana / Search history
Remove-Item -Path "$env:LOCALAPPDATA\Packages\Microsoft.Windows.Search_*\LocalState\*" -Recurse -Force -ErrorAction SilentlyContinue

# Activity Timeline
Remove-Item -Path "$env:LOCALAPPDATA\ConnectedDevicesPlatform\*" -Recurse -Force -ErrorAction SilentlyContinue

# Notification history
Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\Windows\Notifications\*" -Force -ErrorAction SilentlyContinue

# Clipboard history
Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Clipboard" -Name * -Force -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "=== CLEANUP COMPLETE ===" -ForegroundColor Green
Write-Host ""
Write-Host "NOTE: Some files are locked by running processes." -ForegroundColor Cyan
Write-Host "For best results, run at shutdown or from a secondary OS." -ForegroundColor Cyan
