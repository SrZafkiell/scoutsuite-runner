param(
    [string]$ImageName = "local/scoutsuite-runner:5.14.0"
)

$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path "$PSScriptRoot\.."

Write-Host "Building ScoutSuite Docker image: $ImageName"
docker build -t $ImageName $RepoRoot

Write-Host "Done."
