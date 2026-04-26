<#
.SYNOPSIS
    Resolves IP addresses to geographic location using ip-api.com (free tier).
.DESCRIPTION
    Accepts a list of IPs from a file or pipeline and returns country, city,
    ISP, and org data. Rate-limited to stay within free API constraints.
.PARAMETER InputFile
    Path to a text file with one IP per line.
.PARAMETER IPs
    Array of IP address strings passed directly.
.EXAMPLE
    .\geoip-lookup.ps1 -InputFile .\suspect-ips.txt
    .\geoip-lookup.ps1 -IPs @("203.0.113.45", "198.51.100.12")
#>

[CmdletBinding()]
param(
    [Parameter(ParameterSetName="File")]
    [string]$InputFile,

    [Parameter(ParameterSetName="Direct", ValueFromPipeline)]
    [string[]]$IPs
)

function Resolve-GeoIP {
    param([string]$IPAddress)

    $uri = "http://ip-api.com/json/${IPAddress}?fields=status,message,country,regionName,city,isp,org,lat,lon,query"

    try {
        $response = Invoke-RestMethod -Uri $uri -Method Get -TimeoutSec 10

        if ($response.status -eq "fail") {
            Write-Warning "Lookup failed for ${IPAddress}: $($response.message)"
            return $null
        }

        [PSCustomObject]@{
            IP      = $response.query
            Country = $response.country
            Region  = $response.regionName
            City    = $response.city
            ISP     = $response.isp
            Org     = $response.org
            Lat     = $response.lat
            Lon     = $response.lon
        }
    }
    catch {
        Write-Warning "Request failed for ${IPAddress}: $_"
        return $null
    }
}

# Collect IPs from file or parameter
$ipList = @()

if ($InputFile) {
    if (-not (Test-Path $InputFile)) {
        Write-Error "File not found: $InputFile"
        exit 1
    }
    $ipList = Get-Content $InputFile | Where-Object { $_.Trim() -ne "" }
}
elseif ($IPs) {
    $ipList = $IPs
}
else {
    Write-Error "Provide -InputFile or -IPs parameter."
    exit 1
}

Write-Host "Resolving $($ipList.Count) IP(s)..." -ForegroundColor Gray

$results = @()

foreach ($ip in $ipList) {
    $ip = $ip.Trim()
    $result = Resolve-GeoIP -IPAddress $ip

    if ($result) {
        $results += $result
        Write-Host "[+] $($result.IP) -> $($result.City), $($result.Country) [$($result.ISP)]" -ForegroundColor White
    }

    # Rate limit: ip-api free tier allows 45 requests/minute
    Start-Sleep -Milliseconds 1400
}

# Output as table and export to CSV
$results | Format-Table -AutoSize
$outputPath = "geoip-results-$(Get-Date -Format 'yyyyMMdd-HHmmss').csv"
$results | Export-Csv -Path $outputPath -NoTypeInformation
Write-Host "`nResults exported to $outputPath" -ForegroundColor Gray
