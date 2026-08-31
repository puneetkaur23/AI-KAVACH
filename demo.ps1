param(
    [string]$Target = "targets/vuln_bof",
    [int]$Timeout = 30
)

$Host.UI.RawUI.WindowTitle = "AI Kavach - Cyber Reasoning System"

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "             AI KAVACH - CYBER REASONING SYSTEM" -ForegroundColor Yellow
Write-Host "      Autonomous Vulnerability Detection and Patching" -ForegroundColor White
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

$env:PYTHONUTF8 = "1"

Write-Host "[1/3] Checking Docker Sandbox Containers..." -ForegroundColor Green

$dockerState = docker ps --filter "name=kavach_validator" --format "{{.Status}}"

if (-not $dockerState) {
    Write-Host "Starting Docker Sandbox containers..." -ForegroundColor Yellow
    docker compose up -d validator fuzzer

    if ($LASTEXITCODE -ne 0) {
        Write-Host "Docker containers failed to start." -ForegroundColor Red
        exit 1
    }
}
else {
    Write-Host "Docker Sandbox containers are active." -ForegroundColor Green
}

Write-Host ""
Write-Host "[2/3] Executing Cyber Reasoning Pipeline..." -ForegroundColor Green
Write-Host "Target: $Target" -ForegroundColor White
Write-Host "Timeout: $Timeout seconds" -ForegroundColor White
Write-Host ""

py -3 kavach.py --target $Target --timeout $Timeout

Write-Host ""
Write-Host "[3/3] Inspecting Proof-of-Fix Artifacts..." -ForegroundColor Green

$reportDirectory = "output\reports"

if (Test-Path $reportDirectory) {

    $latestHtml = Get-ChildItem "$reportDirectory\*.html" |
        Sort-Object LastWriteTime -Descending |
        Select-Object -First 1

    if ($latestHtml) {
        Write-Host "Proof-of-Fix Report found:" -ForegroundColor Cyan
        Write-Host $latestHtml.FullName -ForegroundColor White
        Start-Process $latestHtml.FullName
    }
    else {
        Write-Host "No HTML report was generated." -ForegroundColor Yellow
    }

}
else {
    Write-Host "Report directory does not exist yet." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "              AI KAVACH DEMO RUN COMPLETE" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan