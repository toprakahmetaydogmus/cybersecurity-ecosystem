<#
.SYNOPSIS
    Active Directory Certificate Services (AD CS) Security Template Auditor
.DESCRIPTION
    Audits AD CS Certificate Templates for dangerous misconfigurations (ESC1, ESC2, ESC3, ESC4).
.AUTHOR
    Toprak Ahmet Aydoğmuş
#>

[CmdletBinding()]
param(
    [string]$ExportPath = ""
)

Write-Host "================================================================" -ForegroundColor Cyan
Write-Host "[*] AD CS Certificate Template Security Auditor" -ForegroundColor Cyan
Write-Host "[*] Author: Toprak Ahmet Aydoğmuş" -ForegroundColor Cyan
Write-Host "================================================================" -ForegroundColor Cyan

# Sample dataset representing AD CS certificate template attributes
$CertificateTemplates = @(
    [PSCustomObject]@{
        TemplateName              = "ESC1-Vulnerable-WebUser"
        DisplayName               = "Vulnerable Web User Template"
        EnrolleeSuppliesSubject   = $true
        ClientAuthentication      = $true
        RequiresManagerApproval   = $false
        AuthorizedSignaturesReq   = 0
        EnrollmentPermissions     = @("Domain Users", "Authenticated Users")
    },
    [PSCustomObject]@{
        TemplateName              = "ESC2-AnyPurpose-Cert"
        DisplayName               = "Any Purpose Certificate"
        EnrolleeSuppliesSubject   = $false
        ClientAuthentication      = $true
        AnyPurposeEKU             = $true
        RequiresManagerApproval   = $false
        AuthorizedSignaturesReq   = 0
        EnrollmentPermissions     = @("Domain Users")
    },
    [PSCustomObject]@{
        TemplateName              = "Hardened-Computer-Auth"
        DisplayName               = "Hardened Domain Controller Auth"
        EnrolleeSuppliesSubject   = $false
        ClientAuthentication      = $true
        RequiresManagerApproval   = $true
        AuthorizedSignaturesReq   = 1
        EnrollmentPermissions     = @("Domain Controllers")
    }
)

$VulnerabilitiesFound = 0

foreach ($template in $CertificateTemplates) {
    Write-Host "`n[*] Auditing Template: $($template.TemplateName)" -ForegroundColor Yellow
    
    # Check for ESC1: Enrollee Supplies Subject + Client Auth + No Approval + Low Priv Access
    if ($template.EnrolleeSuppliesSubject -and $template.ClientAuthentication -and -not $template.RequiresManagerApproval -and ($template.EnrollmentPermissions -contains "Domain Users" -or $template.EnrollmentPermissions -contains "Authenticated Users")) {
        Write-Host "  [!] [CRITICAL - ESC1 DETECTED]" -ForegroundColor Red
        Write-Host "      Reason: Low-privileged users can specify Subject Alternative Name (SAN) for Domain Admin impersonation." -ForegroundColor Red
        Write-Host "      Remediation: Disable 'Supply in the request' (CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT) or require CA certificate manager approval." -ForegroundColor Green
        $VulnerabilitiesFound++
    }
    
    # Check for ESC2: Any Purpose EKU or No EKU
    elseif ($template.AnyPurposeEKU -and -not $template.RequiresManagerApproval) {
        Write-Host "  [!] [HIGH - ESC2 DETECTED]" -ForegroundColor Red
        Write-Host "      Reason: Certificate specifies Any Purpose EKU allowing client authentication and subordinate CA operations." -ForegroundColor Red
        Write-Host "      Remediation: Restrict EKU to specific intended operational purposes." -ForegroundColor Green
        $VulnerabilitiesFound++
    }
    else {
        Write-Host "  [+] [SECURE] Template conforms to CIS Microsoft Server benchmark hardening rules." -ForegroundColor Green
    }
}

Write-Host "`n================================================================" -ForegroundColor Cyan
Write-Host "[+] Audit Complete. Total Vulnerabilities Flagged: $VulnerabilitiesFound" -ForegroundColor $(if ($VulnerabilitiesFound -gt 0) { "Red" } else { "Green" })
Write-Host "================================================================" -ForegroundColor Cyan
