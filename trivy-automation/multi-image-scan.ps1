param (
    [Parameter(Mandatory = $true)]
    [string]$ImageListFile,

    [Parameter(Mandatory = $true)]
    [string]$ReportDirectory
)

# Check if trivy.exe is available
if (-not (Get-Command "trivy" -ErrorAction SilentlyContinue)) {
    Write-Error "trivy not found in the current directory. Please ensure it is present."
    exit 1
}

# Check if image list file exists
if (-not (Test-Path $ImageListFile)) {
    Write-Error "Image list file '$ImageListFile' not found."
    exit 1
}

# Ensure report directory exists
if (-not (Test-Path $ReportDirectory)) {
    New-Item -Path $ReportDirectory -ItemType Directory | Out-Null
}

# Read images and process
Get-Content $ImageListFile | ForEach-Object {
    $image = $_.Trim()
    if ($image) {
        # Sanitize image name for filename
        $safeImageName = $image -replace '[^a-zA-Z0-9_-]', '_'
        $reportPath = Join-Path $ReportDirectory "$safeImageName.html"

        Write-Output "Scanning image: $image"
        trivy image --format template --template "@contrib/html.tpl" -o $reportPath $image

        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Trivy scan failed for image: $image"
        } else {
            Write-Output "Report generated: $reportPath"
        }
    }
}
