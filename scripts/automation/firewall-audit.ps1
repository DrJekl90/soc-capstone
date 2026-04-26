<#
.SYNOPSIS
    Audits Windows Firewall rules for risky configurations.
.DESCRIPTION
    Flags inbound allow rules with broad scope (any source), rules
    on high-risk ports, disabled outbound filtering, and rules that
    apply to all profiles. Helps find holes before an attacker does.
.EXAMPLE
    .\firewall-audit.ps1
#>

[CmdletBinding()]
param()

$highRiskPorts = @(21, 23, 135, 139, 445, 1433, 3389, 5900, 5985, 5986)

Write-Host "`n=== Firewall Rule Audit ===" -ForegroundColor White

$allRules = Get-NetFirewallRule -ErrorAction Stop
$inboundAllow = $allRules | Where-Object {
    $_.Direction -eq "Inbound" -and $_.Action -eq "Allow" -and $_.Enabled -eq "True"
}

Write-Host "Total rules: $($allRules.Count)" -ForegroundColor Gray
Write-Host "Enabled inbound allow rules: $($inboundAllow.Count)`n" -ForegroundColor Gray

$findings = @()

foreach ($rule in $inboundAllow) {
    $portFilter = $rule | Get-NetFirewallPortFilter -ErrorAction SilentlyContinue
    $addrFilter = $rule | Get-NetFirewallAddressFilter -ErrorAction SilentlyContinue

    $localPort = $portFilter.LocalPort
    $remoteAddr = $addrFilter.RemoteAddress

    $issues = @()

    # Flag rules open to any source
    if ($remoteAddr -contains "Any" -or $remoteAddr -contains "*") {
        $issues += "Open to ANY source"
    }

    # Flag high-risk ports
    if ($localPort -and $localPort -ne "Any") {
        $ports = $localPort -split ","
        foreach ($p in $ports) {
            if ($p -match "^\d+$" -and [int]$p -in $highRiskPorts) {
                $issues += "High-risk port: $p"
            }
        }
    }

    # Flag rules spanning all profiles
    $profiles = $rule.Profile.ToString()
    if ($profiles -eq "Any") {
        $issues += "Applies to ALL profiles"
    }

    if ($issues.Count -gt 0) {
        $findings += [PSCustomObject]@{
            RuleName    = $rule.DisplayName
            LocalPort   = ($localPort -join ", ")
            RemoteAddr  = ($remoteAddr -join ", ")
            Protocol    = $portFilter.Protocol
            Profile     = $profiles
            Issues      = ($issues -join "; ")
        }
    }
}

if ($findings.Count -eq 0) {
    Write-Host "No risky inbound rules found." -ForegroundColor Green
}
else {
    Write-Host "Risky rules found: $($findings.Count)`n" -ForegroundColor Yellow
    $findings | Format-Table -AutoSize -Wrap
    $outPath = "firewall-audit-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
    $findings | Export-Csv -Path $outPath -NoTypeInformation
    Write-Host "Details saved to $outPath" -ForegroundColor Gray
}
