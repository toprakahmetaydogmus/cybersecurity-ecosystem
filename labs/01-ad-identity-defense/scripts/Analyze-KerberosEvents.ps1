<#
.SYNOPSIS
    Kerberos Ticket-Granting Service (TGS) Request Analyzer
.DESCRIPTION
    Analyzes Security Event 4769 to detect Kerberoasting attacks via RC4 (0x17) encryption downgrades.
.AUTHOR
    Toprak Ahmet Aydoğmuş
#>

Write-Host "[*] Kerberos Event 4769 Analyzer Initialized..." -ForegroundColor Cyan

$MockKerberosEvents = @(
    @{ EventID = 4769; ServiceName = "krbtgt"; TicketEncryptionType = "0x12"; ClientIP = "10.10.10.50"; TargetUser = "labadmin"; Status = "0x0" },
    @{ EventID = 4769; ServiceName = "MSSQLSvc/sql01.lab.local:1433"; TicketEncryptionType = "0x17"; ClientIP = "10.10.10.99"; TargetUser = "attacker_sim"; Status = "0x0" },
    @{ EventID = 4769; ServiceName = "HTTP/web01.lab.local"; TicketEncryptionType = "0x13"; ClientIP = "10.10.10.51"; TargetUser = "developer01"; Status = "0x0" }
)

foreach ($event in $MockKerberosEvents) {
    # 0x17 = RC4-HMAC (Weak, vulnerable to offline cracking)
    # 0x12 = AES256-CTS-HMAC-SHA1-96 (Strong)
    # 0x13 = AES128-CTS-HMAC-SHA1-96 (Strong)
    if ($event.TicketEncryptionType -eq "0x17" -and $event.ServiceName -ne "krbtgt") {
        Write-Host "[!] [ALERT - KERBEROASTING SUSPECTED]" -ForegroundColor Red
        Write-Host "    Source IP:    $($event.ClientIP)" -ForegroundColor Yellow
        Write-Host "    Target SPN:   $($event.ServiceName)" -ForegroundColor Yellow
        Write-Host "    User:         $($event.TargetUser)" -ForegroundColor Yellow
        Write-Host "    Encryption:   RC4-HMAC (0x17) - Potential ticket extraction for offline cracking!" -ForegroundColor Red
    } else {
        Write-Host "[+] Legitimate TGS Request: $($event.ServiceName) (Encryption: $($event.TicketEncryptionType))" -ForegroundColor Green
    }
}
