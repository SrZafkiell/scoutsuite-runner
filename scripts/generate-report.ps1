param(
    [string]$Client = "",

    [string]$RunDir = "",

    [string]$ProjectFilter = "",

    [ValidateSet("Critical", "High", "Medium", "Low", "Informational")]
    
    [string]$MinSeverity = "Informational",

    [string]$ImageName = "local/scoutsuite-runner:5.14.0"
)

$ErrorActionPreference = "Stop"

function Get-RelativePathCompat {
    param(
        [Parameter(Mandatory = $true)]
        [string]$BasePath,

        [Parameter(Mandatory = $true)]
        [string]$TargetPath
    )

    $BaseResolved = (Resolve-Path $BasePath).Path
    $TargetResolved = (Resolve-Path $TargetPath).Path

    if (-not $BaseResolved.EndsWith([System.IO.Path]::DirectorySeparatorChar)) {
        $BaseResolved += [System.IO.Path]::DirectorySeparatorChar
    }

    $BaseUri = New-Object System.Uri($BaseResolved)
    $TargetUri = New-Object System.Uri($TargetResolved)

    $RelativeUri = $BaseUri.MakeRelativeUri($TargetUri)
    $RelativePath = [System.Uri]::UnescapeDataString($RelativeUri.ToString())

    return ($RelativePath -replace '/', '\')
}

$RepoRoot = Resolve-Path "$PSScriptRoot\.."
$RepoRootPath = $RepoRoot.Path
$ReportsRoot = Join-Path $RepoRootPath "reports"

if ($RunDir.Trim() -eq "") {
    if ($Client.Trim() -eq "") {
        throw "Provide either -Client or -RunDir."
    }

    $SafeClient = $Client -replace '[^a-zA-Z0-9._-]', '-'
    $ClientReportsDir = Join-Path $ReportsRoot $SafeClient

    if (!(Test-Path $ClientReportsDir)) {
        throw "No reports folder found for client: $SafeClient"
    }

    $LatestDir = Get-ChildItem -Path $ClientReportsDir -Directory |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($null -eq $LatestDir) {
        throw "No report runs found for client: $SafeClient"
    }

    $RunDirPath = $LatestDir.FullName
} else {
    $RunDirPath = (Resolve-Path $RunDir).Path

    if ($Client.Trim() -eq "") {
        $Client = Split-Path (Split-Path $RunDirPath -Parent) -Leaf
    }

    $SafeClient = $Client -replace '[^a-zA-Z0-9._-]', '-'
}

$RelativeRunDir = Get-RelativePathCompat -BasePath $RepoRootPath -TargetPath $RunDirPath
$RelativeRunDirDocker = $RelativeRunDir -replace '\\', '/'
$RunDirDocker = "/work/$RelativeRunDirDocker"

$RepoRootDocker = $RepoRootPath -replace '\\', '/'

Write-Host "Generating report draft..."
Write-Host "Client:  $SafeClient"
Write-Host "Run dir: $RunDirPath"
Write-Host "Minimum severity: $MinSeverity"

if ($ProjectFilter.Trim() -ne "") {
    Write-Host "Filter:  $ProjectFilter"
}

Write-Host ""

$GeneratorArgs = @(
    "tools/generate_report.py",
    "--run-dir", $RunDirDocker,
    "--client", $SafeClient,
    "--min-severity", $MinSeverity
)

if ($ProjectFilter.Trim() -ne "") {
    $GeneratorArgs += "--project-filter"
    $GeneratorArgs += $ProjectFilter
}

docker run --rm `
    --entrypoint python `
    -v "${RepoRootDocker}:/work" `
    -w /work `
    $ImageName `
    @GeneratorArgs

Write-Host ""
Write-Host "Generated files:"
Write-Host (Join-Path $RunDirPath "generated")