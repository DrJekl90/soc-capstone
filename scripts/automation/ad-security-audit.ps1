<#
.SYNOPSIS
    Pulls a quick security snapshot of an Active Directory environment.
.DESCRIPTION
    Checks for stale accounts, never-expiring passwords, privileged
    group membership, and dormant computer objects. Outputs a summary
    to the console and a detailed CSV. Does not make any changes.
.EXAMPLE
    .\ad-security-audit.ps1
    .\ad-security-audit.ps1 -DaysInactive 60 -OutputDir C:\Reports
#>

[CmdletBinding()]
param(
    [int]$DaysInactive = 90,
    [string]$OutputDir = "."
)

Import-Module ActiveDirectory -ErrorAction Stop

$cutoffDate = (Get-Date).AddDays(-$DaysInactive)
$timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$findings = @()

Write-Host "`n=== AD Security Audit ===" -ForegroundColor White
Write-Host "Inactive threshold: $DaysInactive days" -ForegroundColor Gray
Write-Host "Cutoff date: $cutoffDate`n" -ForegroundColor Gray

# --- Stale user accounts ---
$staleUsers = Get-ADUser -Filter {
    LastLogonDate -lt $cutoffDate -and Enabled -eq $true
} -Properties LastLogonDate, PasswordLastSet, Description |
Select-Object SamAccountName, Name, LastLogonDate, PasswordLastSet, Description

Write-Host "[1] Stale enabled accounts (no logon in ${DaysInactive}d): $($staleUsers.Count)" -ForegroundColor Yellow

foreach ($u in $staleUsers) {
    $findings += [PSCustomObject]@{
        Category = "Stale Account"
        Identity = $u.SamAccountName
        Detail   = "Last logon: $($u.LastLogonDate)"
        Risk     = "Medium"
    }
}

# --- Passwords set to never expire ---
$neverExpire = Get-ADUser -Filter {
    PasswordNeverExpires -eq $true -and Enabled -eq $true
} -Properties PasswordNeverExpires, PasswordLastSet |
Select-Object SamAccountName, PasswordLastSet

Write-Host "[2] Accounts with non-expiring passwords: $($neverExpire.Count)" -ForegroundColor Yellow

foreach ($u in $neverExpire) {
    $findings += [PSCustomObject]@{
        Category = "Never-Expire Password"
        Identity = $u.SamAccountName
        Detail   = "Password set: $($u.PasswordLastSet)"
        Risk     = "High"
    }
}

# --- Privileged group membership ---
$privGroups = @(
    "Domain Admins",
    "Enterprise Admins",
    "Schema Admins",
    "Administrators",
    "Account Operators",
    "Backup Operators"
)

foreach ($group in $privGroups) {
    try {
        $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
        $count = ($members | Measure-Object).Count
        Write-Host "[3] $group members: $count" -ForegroundColor Yellow

        foreach ($m in $members) {
            $findings += [PSCustomObject]@{
                Category = "Privileged Group"
                Identity = $m.SamAccountName
                Detail   = "Member of: $group"
                Risk     = "Info"
            }
        }
    }
    catch {
        Write-Host "  Could not query $group" -ForegroundColor Gray
    }
}

# --- Dormant computer objects ---
$staleComputers = Get-ADComputer -Filter {
    LastLogonDate -lt $cutoffDate -and Enabled -eq $true
} -Properties LastLogonDate, OperatingSystem |
Select-Object Name, LastLogonDate, OperatingSystem

Write-Host "[4] Dormant computer objects: $($staleComputers.Count)" -ForegroundColor Yellow

foreach ($c in $staleComputers) {
    $findings += [PSCustomObject]@{
        Category = "Dormant Computer"
        Identity = $c.Name
        Detail   = "OS: $($c.OperatingSystem), Last seen: $($c.LastLogonDate)"
        Risk     = "Low"
    }
}

# --- Export ---
$outputPath = Join-Path $OutputDir "ad-audit-$timestamp.csv"
$findings | Export-Csv -Path $outputPath -NoTypeInformation
Write-Host "`nTotal findings: $($findings.Count)" -ForegroundColor White
Write-Host "Report saved to $outputPath`n" -ForegroundColor Gray
