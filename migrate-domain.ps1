# migrate-domain.ps1 - tunggu zone jadi active, lalu setup email routing + D1.
# Pakai:
#   $env:CLOUDFLARE_API_TOKEN = "..."
#   pwsh -File .\migrate-domain.ps1 -Domain mail.example.com [-Premium] [-IntervalSec 60] [-MaxMinutes 120]
param(
  [Parameter(Mandatory=$true)][string]$Domain,
  [switch]$Premium,
  [int]$IntervalSec = 60,
  [int]$MaxMinutes = 120
)
$ErrorActionPreference = "Stop"
$Domain = $Domain.Trim().ToLower()
$h = @{ Authorization = "Bearer $env:CLOUDFLARE_API_TOKEN" }
$api = "https://api.cloudflare.com/client/v4"
$deadline = (Get-Date).AddMinutes($MaxMinutes)
$round = 0
while ((Get-Date) -lt $deadline) {
  $round++
  $z = Invoke-RestMethod -Uri "$api/zones?name=$Domain" -Headers $h
  if (-not $z.result.Count) { Write-Host "[-] zone $Domain tidak ada di akun ini" -ForegroundColor Red; exit 1 }
  $status = $z.result[0].status
  Write-Host ("[{0}] putaran {1} - status: {2}" -f (Get-Date -Format "HH:mm:ss"), $round, $status) -ForegroundColor Cyan
  if ($status -eq "active") {
    Write-Host "[ok] zone active, menjalankan add-domain.ps1" -ForegroundColor Green
    $args = @("-File", ".\add-domain.ps1", "-Domain", $Domain)
    if ($Premium) { $args += "-Premium" }
    & pwsh @args
    exit $LASTEXITCODE
  }
  Write-Host ("     NS: " + ($z.result[0].name_servers -join " , ")) -ForegroundColor Yellow
  Start-Sleep -Seconds $IntervalSec
}
Write-Host "[-] timeout menunggu aktivasi. Cek Zone Hold di akun lama / NS di registrar." -ForegroundColor Red
exit 2
