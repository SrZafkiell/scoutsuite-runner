$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path "$PSScriptRoot\.."
$AwsDir = Join-Path $RepoRoot "secrets\aws"
$CredentialsPath = Join-Path $AwsDir "credentials"
$ConfigPath = Join-Path $AwsDir "config"

New-Item -ItemType Directory -Force -Path $AwsDir | Out-Null

if (!(Test-Path $CredentialsPath)) {
@"
[scout-audit]
aws_access_key_id = REPLACE_ME
aws_secret_access_key = REPLACE_ME
"@ | Set-Content -Encoding ascii $CredentialsPath
    Write-Host "Created $CredentialsPath"
} else {
    Write-Host "Already exists: $CredentialsPath"
}

if (!(Test-Path $ConfigPath)) {
@"
[profile scout-audit]
region = us-east-1
output = json
"@ | Set-Content -Encoding ascii $ConfigPath
    Write-Host "Created $ConfigPath"
} else {
    Write-Host "Already exists: $ConfigPath"
}

Write-Host ""
Write-Host "Edit the files above with your temporary scout-audit credentials."
Write-Host "These files are ignored by Git."
