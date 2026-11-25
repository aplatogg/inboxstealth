# wait-domain.ps1 — tunggu zone Cloudflare jadi "active", lalu (opsional) setup temp mail.
# Pakai:
#   $env:CLOUDFLARE_API_TOKEN = "..."
#   pwsh -File .\wait-domain.ps1 -Domain mail.example.com -Premium -Setup
#
# -Setup  : jalankan add-domain.ps1 otomatis begitu active
# -TimeoutMinutes : batas tunggu (default 120)

param(
  [Parameter(Mandatory=$true)][string]$Domain,
  [int]$TimeoutMinutes = 120,
  [switch]$Setup,
  [switch]$Premium
)

$ErrorActionPreference = "Stop"
if (-not $env:CLOUDFLARE_API_TOKEN) { Write-Host "[-] set CLOUDFLARE_API_TOKEN dulu" -ForegroundColor Red; exit 1 }

$h = @{ Authorization = "Bearer $env:CLOUDFLARE_API_TOKEN" }
$api = "https://api.cloudflare.com/client/v4"
$deadline = (Get-Date).AddMinutes($TimeoutMinutes)
$i = 0

Write-Host "menunggu $Domain aktif (maks $TimeoutMinutes menit)..." -ForegroundColor Cyan

while ((Get-Date) -lt $deadline) {
  $i++
  try {
    $z = Invoke-RestMethod -Uri "$api/zones?name=$Domain" -Headers $h
    if (-not $z.result.Count) { Write-Host "[-] zone tidak ada" -ForegroundColor Red; exit 2 }

    $zid = $z.result[0].id
    $status = $z.result[0].status
    Write-Host ("[{0}] {1} status={2}" -f $i, (Get-Date -Format "HH:mm:ss"), $status)

    if ($status -eq "active") {
      Write-Host "[ok] $Domain aktif" -ForegroundColor Green
      if ($Setup) {
        $args = @("-Domain", $Domain)
        if ($Premium) { $args += "-Premium" }
        & pwsh -NoProfile -File (Join-Path $PSScriptRoot "add-domain.ps1") @args
      }
      exit 0
    }

    # trigger cek ulang tiap 5 putaran
    if ($i % 5 -eq 0) {
      try { $null = Invoke-RestMethod -Uri "$api/zones/$zid/activation_check" -Method PUT -Headers $h -ContentType "application/json" -Body "{}" } catch {}
    }
  } catch {
    Write-Host ("[{0}] error: {1}" -f $i, $_.Exception.Message) -ForegroundColor Yellow
  }
  Start-Sleep -Seconds 30
}

Write-Host "[-] timeout. Cek lagi manual nanti: zone masih pending." -ForegroundColor Red
exit 3
