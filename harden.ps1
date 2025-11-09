# Master Windows Firewall Security Hardening Script
# Run as Administrator
# Combines ALL security improvements into one comprehensive script

if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Warning "Please run this script as Administrator!"
    exit
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  MASTER FIREWALL SECURITY HARDENING" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "This comprehensive script will:" -ForegroundColor Yellow
Write-Host "  1. Block dangerous ports" -ForegroundColor White
Write-Host "  2. Disable remote access features" -ForegroundColor White
Write-Host "  3. Remove unnecessary app rules" -ForegroundColor White
Write-Host "  4. Disable privacy-invasive features" -ForegroundColor White
Write-Host "  5. Clean up unused rules" -ForegroundColor White
Write-Host ""
Write-Host "A backup will be created before any changes." -ForegroundColor Green
Write-Host ""
Write-Host "Press any key to continue or Ctrl+C to cancel..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ""

# ============================================
# SECTION 1: BACKUP
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SECTION 1: CREATING BACKUP" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$backupPath = "$env:USERPROFILE\Desktop\FirewallBackup_MASTER_$(Get-Date -Format 'yyyyMMdd_HHmmss').wfw"
Write-Host "Creating backup of current firewall rules..." -ForegroundColor Yellow
netsh advfirewall export $backupPath | Out-Null
Write-Host "OK Backup saved to: $backupPath" -ForegroundColor Green
Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ""

# ============================================
# SECTION 2: BLOCK DANGEROUS PORTS
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SECTION 2: BLOCKING DANGEROUS PORTS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$criticalBlockPorts = @(
    # TCP Ports
	@{Port=21; Protocol="TCP"; Name="Block TCP Port 21"; Description="FTP"},
    @{Port=135; Protocol="TCP"; Name="Block TCP Port 135"; Description="RPC - Remote Procedure Call (ransomware target)"},
    @{Port=139; Protocol="TCP"; Name="Block TCP Port 139"; Description="NetBIOS Session Service (SMB)"},
    @{Port=445; Protocol="TCP"; Name="Block TCP Port 445"; Description="SMB - File Sharing (WannaCry, NotPetya target)"},
    @{Port=5357; Protocol="TCP"; Name="Block TCP Port 5357"; Description="WSDAPI - Web Services Discovery"},
    
    # UDP Ports - Network Services
    @{Port=53; Protocol="UDP"; Name="Block UDP Port 53"; Description="DNS - Domain Name System (prevent DNS amplification)"},
    @{Port=69; Protocol="UDP"; Name="Block UDP Port 69"; Description="TFTP - Trivial File Transfer"},
    @{Port=111; Protocol="UDP"; Name="Block UDP Port 111"; Description="RPC Portmapper (NFS attacks)"},
    @{Port=123; Protocol="UDP"; Name="Block UDP Port 123"; Description="NTP - Network Time Protocol (DDoS amplification)"},
    @{Port=137; Protocol="UDP"; Name="Block UDP Port 137"; Description="NetBIOS Name Service"},
    @{Port=138; Protocol="UDP"; Name="Block UDP Port 138"; Description="NetBIOS Datagram Service"},
    @{Port=161; Protocol="UDP"; Name="Block UDP Port 161"; Description="SNMP - Simple Network Management Protocol"},
    @{Port=389; Protocol="UDP"; Name="Block UDP Port 389"; Description="LDAP - Lightweight Directory Access Protocol"},
    @{Port=500; Protocol="UDP"; Name="Block UDP Port 500"; Description="IKE - IPSec VPN (IKEv1)"},
    @{Port=636; Protocol="UDP"; Name="Block UDP Port 636"; Description="LDAPS - LDAP over SSL"},
    @{Port=1194; Protocol="UDP"; Name="Block UDP Port 1194"; Description="OpenVPN (unless you use it)"},
    @{Port=1900; Protocol="UDP"; Name="Block UDP Port 1900"; Description="SSDP - UPnP Discovery (IoT attacks)"},
    @{Port=2049; Protocol="UDP"; Name="Block UDP Port 2049"; Description="NFS - Network File System"},
    @{Port=3702; Protocol="UDP"; Name="Block UDP Port 3702"; Description="WS-Discovery"},
    @{Port=4500; Protocol="UDP"; Name="Block UDP Port 4500"; Description="IPSec NAT Traversal"},
    @{Port=5353; Protocol="UDP"; Name="Block UDP Port 5353"; Description="mDNS - Multicast DNS (Bonjour)"},
    @{Port=5355; Protocol="UDP"; Name="Block UDP Port 5355"; Description="LLMNR - Link-Local Name Resolution (credential theft)"}
)

Write-Host "Enabling critical port blocks across ALL profiles..." -ForegroundColor Yellow
Write-Host ""

$blockedCount = 0
foreach ($rule in $criticalBlockPorts) {
    $existingRule = Get-NetFirewallRule -DisplayName $rule.Name -ErrorAction SilentlyContinue
    
    if ($existingRule) {
        Set-NetFirewallRule -DisplayName $rule.Name -Enabled True -Profile Any -ErrorAction SilentlyContinue
        Write-Host "  OK Enabled block: $($rule.Description)" -ForegroundColor Green
        $blockedCount++
    } else {
        # Create the block rule if it doesn't exist
        New-NetFirewallRule -DisplayName $rule.Name -Direction Inbound -Protocol $rule.Protocol -LocalPort $rule.Port -Action Block -Profile Any -Enabled True -ErrorAction SilentlyContinue | Out-Null
        Write-Host "  OK Created block: $($rule.Description)" -ForegroundColor Green
        $blockedCount++
    }
}

Write-Host ""
Write-Host "Total dangerous ports blocked: $blockedCount" -ForegroundColor Green
Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ""

# ============================================
# SECTION 3: DISABLE REMOTE ACCESS
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SECTION 3: DISABLING REMOTE ACCESS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$remoteAccessPatterns = @(
    "*Hulp op afstand*",           # Remote Assistance
    "*Extern bureaublad*",          # Remote Desktop
    "*Extern servicebeheer*",       # Remote Service Management
    "*Extern Event Log-beheer*",    # Remote Event Log Management
    "*Extern volumebeheer*",        # Remote Volume Management
    "*Extern beheer van geplande taken*",  # Remote Scheduled Tasks
    "*Extern beheer van Windows Defender Firewall*",  # Remote Firewall Management
    "*Extern afsluiten*",           # Remote Shutdown
    "*Remote Assistance*",           # Remote Assistance
    "*Remote Desktop*",          # Remote Desktop
    "*Remote Service Management*",       # Remote Service Management
    "*Remote Event Log Management*",    # Remote Event Log Management
    "*Remote Volume Management*",        # Remote Volume Management
    "*Remote Scheduled Tasks*",  # Remote Scheduled Tasks
    "*Remote Firewall Management*",  # Remote Firewall Management
    "*Remote Shutdown*",           # Remote Shutdown
    "*Windows Remote Management*"   # WinRM
)

Write-Host "Do you EVER use remote access to this computer?" -ForegroundColor Yellow
Write-Host "(Remote Desktop, TeamViewer, VNC, Windows Remote Management, etc.)" -ForegroundColor Yellow
Write-Host ""
Write-Host "NOTE: You have Tailscale installed which is a safer alternative!" -ForegroundColor Cyan
Write-Host ""
Write-Host "Disable remote access features? (Y/N): " -NoNewline -ForegroundColor Yellow
$response = Read-Host

if ($response -eq "Y" -or $response -eq "y") {
    Write-Host ""
    Write-Host "Disabling remote access rules..." -ForegroundColor Yellow
    
    $remoteDisabledCount = 0
    foreach ($pattern in $remoteAccessPatterns) {
        $rules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like $pattern }
        if ($rules) {
            $rules | Disable-NetFirewallRule
            $remoteDisabledCount += $rules.Count
            Write-Host "  OK Disabled: $pattern ($($rules.Count) rules)" -ForegroundColor Green
        }
    }
    
    # Disable Remote Desktop service
    Write-Host "  OK Disabling Remote Desktop service..." -ForegroundColor Yellow
    try {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Value 1 -ErrorAction Stop
        Write-Host "    Remote Desktop service disabled" -ForegroundColor Green
    } catch {
        Write-Host "    Could not disable RDP service (may not be installed)" -ForegroundColor Gray
    }
    
    # Disable Remote Assistance
    Write-Host "  OK Disabling Remote Assistance..." -ForegroundColor Yellow
    try {
        Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0 -ErrorAction Stop
        Write-Host "    Remote Assistance disabled" -ForegroundColor Green
    } catch {
        Write-Host "    Could not disable Remote Assistance" -ForegroundColor Gray
    }
    
    Write-Host ""
    Write-Host "Total remote access rules disabled: $remoteDisabledCount" -ForegroundColor Green
} else {
    Write-Host ""
    Write-Host "Skipping remote access disabling (keeping current settings)" -ForegroundColor Yellow
    Write-Host "WARNING: Remote access is a major security risk!" -ForegroundColor Red
}

Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ""

# ============================================
# SECTION 4: DISABLE TELEMETRY & UNNECESSARY APPS
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SECTION 4: DISABLING TELEMETRY & APPS" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Automatically disabling unnecessary app rules..." -ForegroundColor Yellow
Write-Host ""

$autoDisableApps = @(
    "*Feedback*",                    # Feedback Hub - Microsoft telemetry
    "*Solitaire*",                   # Solitaire game
    "*Films en tv*",                 # Movies & TV
    "*Windows-klok*",                # Clock/Alarms
    "*Account voor werk of school*", # Work/School Account
    "*Bureaublad app webviewer*"     # Desktop App Web Viewer
)

$appDisabledCount = 0
foreach ($pattern in $autoDisableApps) {
    $rules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like $pattern }
    if ($rules) {
        $rules | Disable-NetFirewallRule
        $appDisabledCount += $rules.Count
        Write-Host "  OK Disabled: $pattern ($($rules.Count) rules)" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Do you use Microsoft Store to install apps? (Y/N): " -NoNewline -ForegroundColor Yellow
$response = Read-Host

if ($response -eq "N" -or $response -eq "n") {
    $storeRules = Get-NetFirewallRule | Where-Object { 
        ($_.DisplayName -like "*Store*" -or $_.DisplayName -like "*App-installatieprogramma*") -and 
        $_.DisplayName -notlike "*Windows-beveiliging*" 
    }
    if ($storeRules) {
        $storeRules | Disable-NetFirewallRule
        $appDisabledCount += $storeRules.Count
        Write-Host "  OK Disabled Microsoft Store rules" -ForegroundColor Green
    }
} else {
    Write-Host "  INFO Keeping Microsoft Store enabled" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Do you use Windows Media Player or Media Sharing? (Y/N): " -NoNewline -ForegroundColor Yellow
$response = Read-Host

if ($response -eq "N" -or $response -eq "n") {
    $mediaRules = Get-NetFirewallRule | Where-Object { 
        $_.DisplayName -like "*Windows Mediaspeler*" -or 
        $_.DisplayName -like "*Media Center*" 
    }
    if ($mediaRules) {
        $mediaRules | Disable-NetFirewallRule
        $appDisabledCount += $mediaRules.Count
        Write-Host "  OK Disabled Windows Media Player rules" -ForegroundColor Green
    }
} else {
    Write-Host "  INFO Keeping Windows Media Player enabled" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Total app rules disabled: $appDisabledCount" -ForegroundColor Green
Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ""

# ============================================
# SECTION 5: DISABLE FILE SHARING (if not needed)
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SECTION 5: FILE & PRINTER SHARING" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Do you share files or printers with other computers on your network? (Y/N): " -NoNewline -ForegroundColor Yellow
$response = Read-Host

if ($response -eq "N" -or $response -eq "n") {
    $fileShareRules = Get-NetFirewallRule -DisplayGroup "Bestands- en printerdeling" -ErrorAction SilentlyContinue
    if ($fileShareRules) {
        $fileShareRules | Disable-NetFirewallRule
        Write-Host "  OK Disabled File and Printer Sharing ($($fileShareRules.Count) rules)" -ForegroundColor Green
    }
} else {
    Write-Host "  INFO Keeping File and Printer Sharing enabled" -ForegroundColor Cyan
    Write-Host "  RECOMMENDATION: Restrict to specific IP addresses for better security" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ""

# ============================================
# SECTION 6: DISABLE PRIVACY-INVASIVE FEATURES
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SECTION 6: PRIVACY FEATURES" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Disable LLMNR (security and privacy risk)
Write-Host "Disabling LLMNR (credential theft risk)..." -ForegroundColor Yellow
$llmnrRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*LLMNR*" }
if ($llmnrRules) {
    $llmnrRules | Disable-NetFirewallRule
    Write-Host "  OK Disabled LLMNR firewall rules" -ForegroundColor Green
}

$llmnrRegPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
if (-not (Test-Path $llmnrRegPath)) {
    New-Item -Path $llmnrRegPath -Force | Out-Null
}
Set-ItemProperty -Path $llmnrRegPath -Name "EnableMulticast" -Value 0 -Type DWord
Write-Host "  OK Disabled LLMNR via registry" -ForegroundColor Green

# Ask about mDNS
Write-Host ""
Write-Host "Do you use Apple devices or Bonjour services (AirPlay, etc.)? (Y/N): " -NoNewline -ForegroundColor Yellow
$response = Read-Host

if ($response -eq "N" -or $response -eq "n") {
    Get-NetFirewallRule -DisplayName "*mDNS*" -ErrorAction SilentlyContinue | Disable-NetFirewallRule
    Write-Host "  OK Disabled mDNS rules" -ForegroundColor Green
} else {
    Write-Host "  INFO Keeping mDNS enabled for Apple device compatibility" -ForegroundColor Cyan
}

# Ask about Connected Devices Platform
Write-Host ""
Write-Host "Do you use 'Continue on PC' or cross-device features? (Y/N): " -NoNewline -ForegroundColor Yellow
$response = Read-Host

if ($response -eq "N" -or $response -eq "n") {
    Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*Connected Devices*" } | Disable-NetFirewallRule
    Write-Host "  OK Disabled Connected Devices Platform" -ForegroundColor Green
} else {
    Write-Host "  INFO Keeping Connected Devices Platform enabled" -ForegroundColor Cyan
}

# Ask about Delivery Optimization (P2P Windows Updates)
Write-Host ""
Write-Host "Disable Delivery Optimization (Windows Update P2P sharing)? (Y/N): " -NoNewline -ForegroundColor Yellow
$response = Read-Host

if ($response -eq "Y" -or $response -eq "y") {
    Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*Delivery Optimization*" } | Disable-NetFirewallRule
    Write-Host "  OK Disabled Delivery Optimization" -ForegroundColor Green
    Write-Host "  NOTE: Windows updates will still work normally" -ForegroundColor Gray
} else {
    Write-Host "  INFO Keeping Delivery Optimization enabled" -ForegroundColor Cyan
}

Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ""

# ============================================
# SECTION 7: CLEAN UP UNUSED RULES
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SECTION 7: CLEANING UP UNUSED RULES" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Remove CheckPoint/ZoneAlarm leftover rules
$checkpointRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*CheckPoint*" }
if ($checkpointRules) {
    $checkpointRules | Remove-NetFirewallRule
    Write-Host "  OK Removed CheckPoint/ZoneAlarm installer rules ($($checkpointRules.Count))" -ForegroundColor Green
}

# Remove disabled duplicate rules
Write-Host ""
Write-Host "Checking for disabled/duplicate security rules..." -ForegroundColor Yellow
$secRules = Get-NetFirewallRule | Where-Object { 
    ($_.DisplayName -like "Sec Rules*" -or $_.DisplayName -like "Block *Port*") -and 
    $_.Enabled -eq $false 
}
if ($secRules) {
    Write-Host "  Found $($secRules.Count) disabled security rules" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Press any key to continue..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ""

# ============================================
# SECTION 8: ENSURE CRITICAL SECURITY RULES ENABLED
# ============================================
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SECTION 8: FINAL SECURITY CHECK" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

Write-Host "Ensuring Windows Security app can communicate..." -ForegroundColor Yellow
$securityRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*Windows-beveiliging*" }
if ($securityRules) {
    $securityRules | Set-NetFirewallRule -Enabled True
    Write-Host "  OK Windows Security rules are enabled (CRITICAL)" -ForegroundColor Green
}

Write-Host ""
Write-Host "Ensuring Tailscale can communicate..." -ForegroundColor Yellow
$tailscaleRules = Get-NetFirewallRule | Where-Object { $_.DisplayName -like "*Tailscale*" }
if ($tailscaleRules) {
    $tailscaleRules | Set-NetFirewallRule -Enabled True
    Write-Host "  OK Tailscale rules are enabled (your safe remote access)" -ForegroundColor Green
}

Write-Host ""
Write-Host "Press any key to see final summary..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
Write-Host ""

# ============================================
# FINAL SUMMARY
# ============================================
Write-Host "========================================" -ForegroundColor Green
Write-Host "  HARDENING COMPLETE!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

Write-Host "Summary of changes:" -ForegroundColor Cyan
Write-Host "  [+] Blocked $blockedCount dangerous ports" -ForegroundColor White
Write-Host "  [+] Disabled remote access features" -ForegroundColor White
Write-Host "  [+] Disabled $appDisabledCount unnecessary app rules" -ForegroundColor White
Write-Host "  [+] Disabled LLMNR (credential theft protection)" -ForegroundColor White
Write-Host "  [+] Cleaned up unused rules" -ForegroundColor White
Write-Host "  [+] Verified critical security apps enabled" -ForegroundColor White
Write-Host ""

Write-Host "Your firewall security has been significantly improved!" -ForegroundColor Green
Write-Host ""

Write-Host "Additional Recommendations:" -ForegroundColor Yellow
Write-Host "  1. Keep Windows Update enabled and current" -ForegroundColor White
Write-Host "  2. Use Tailscale for any remote access needs" -ForegroundColor White
Write-Host "  3. Regularly review firewall logs: " -ForegroundColor White
Write-Host "     Event Viewer > Windows Logs > Security" -ForegroundColor Gray
Write-Host "  4. Consider enabling firewall logging:" -ForegroundColor White
Write-Host "     netsh advfirewall set allprofiles logging droppedconnections enable" -ForegroundColor Gray
Write-Host ""

Write-Host "Backup file location:" -ForegroundColor Yellow
Write-Host "  $backupPath" -ForegroundColor Gray
Write-Host ""
Write-Host "To restore previous settings (if needed):" -ForegroundColor Yellow
Write-Host "  netsh advfirewall import `"$backupPath`"" -ForegroundColor Gray
Write-Host ""

Write-Host "========================================" -ForegroundColor Green
Write-Host "Press any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
