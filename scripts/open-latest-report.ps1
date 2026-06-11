param(
    [Parameter(Mandatory = $true)]
    [string]$Client
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path "$PSScriptRoot\.."
$SafeClient = $Client -replace '[^a-zA-Z0-9._-]', '-'
$ClientReportsDir = Join-Path $RepoRoot "reports\$SafeClient"

if (!(Test-Path $ClientReportsDir)) {
    throw "No reports found for client: $SafeClient"
}

$LatestDir = Get-ChildItem -Path $ClientReportsDir -Directory |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

if ($null -eq $LatestDir) {
    throw "No report folders found for client: $SafeClient"
}

$Html = Get-ChildItem -Path $LatestDir.FullName -Filter "*.html" |
    Select-Object -First 1

if ($null -eq $Html) {
    throw "No HTML report found in latest folder: $($LatestDir.FullName)"
}

Start-Process $Html.FullName
Write-Host "Opened: $($Html.FullName)"
