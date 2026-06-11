param(
    [Parameter(Mandatory = $true)]
    [string]$Client,

    [string]$Profile = "scout-audit",

    [string]$ImageName = "local/scoutsuite-runner:5.14.0",

    [string]$Region = "us-east-1",

    [string]$Services = ""
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path "$PSScriptRoot\.."
$AwsDir = Join-Path $RepoRoot "secrets\aws"
$ReportsRoot = Join-Path $RepoRoot "reports"

if (!(Test-Path (Join-Path $AwsDir "credentials"))) {
    throw "Missing secrets\aws\credentials. Run .\scripts\init-aws-creds.ps1 first."
}

if (!(Test-Path (Join-Path $AwsDir "config"))) {
    throw "Missing secrets\aws\config. Run .\scripts\init-aws-creds.ps1 first."
}

$SafeClient = $Client -replace '[^a-zA-Z0-9._-]', '-'
$Timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$RunDir = Join-Path $ReportsRoot "$SafeClient\$Timestamp"

New-Item -ItemType Directory -Force -Path $RunDir | Out-Null

$AwsDirDocker = ($AwsDir -replace '\\', '/')
$RunDirDocker = ($RunDir -replace '\\', '/')

Write-Host "Running ScoutSuite AWS report..."
Write-Host "Client:  $SafeClient"
Write-Host "Profile: $Profile"
Write-Host "Output:  $RunDir"

if ($Services.Trim() -ne "") {
    Write-Host "Services: $Services"
} else {
    Write-Host "Services: all"
}

Write-Host ""

$ScoutArgs = @(
    "aws",
    "--profile", $Profile,
    "--no-browser",
    "--report-dir", "/reports"
)

if ($Services.Trim() -ne "") {
    $ScoutArgs += "--services"
    $ScoutArgs += $Services.Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)
}

docker run --rm -it `
    -e AWS_PROFILE=$Profile `
    -e AWS_DEFAULT_REGION=$Region `
    -e AWS_RETRY_MODE=adaptive `
    -e AWS_MAX_ATTEMPTS=10 `
    -v "${AwsDirDocker}:/root/.aws:ro" `
    -v "${RunDirDocker}:/reports" `
    $ImageName `
    @ScoutArgs

Write-Host ""
Write-Host "Report generated at:"
Write-Host $RunDir
