# check.ps1 — health check temp mail (read-only)
# Pakai:  pwsh -File .\check.ps1
#         pwsh -File .\check.ps1 -Url https://mail.example.com -Domains mail.example.com,inbox.example.org
#
# Cek: UI hidup, API domain, MX tiap domain, Email Routing enabled,
#      catch-all mengarah ke worker, dan isi tabel domains di D1.
# Tanpa API token: bagian Cloudflare dilewati (MX tetap dicek via DNS publik).

param(
  [string]$Url = "https://mail.example.com",
  [string[]]$Domains = @("mail.example.com"),
  [string]$WorkerName = "tempmail",
  [string]$Email,
  [string]$Password,
  [string]$CaptchaToken = ""
)

$ErrorActionPreference = "Continue"
# dukung -Domains "a,b,c" dari CLI
if ($Domains.Count -eq 1 -and $Domains[0] -match ",") { $Domains = @($Domains[0] -split "," | ForEach-Object { $_.Trim() }) }
$fail = 0

function Ok($m)   { Write-Host "[ok]   $m" -ForegroundColor Green }
function Bad($m)  { Write-Host "[FAIL] $m" -ForegroundColor Red; $script:fail++ }
function Info($m) { Write-Host "[info] $m" -ForegroundColor Cyan }
function Skip($m) { Write-Host "[skip] $m" -ForegroundColor DarkGray }

Write-Host "temp mail health — $Url" -ForegroundColor Magenta

# 1. UI
try {
  $r = Invoke-WebRequest -Uri $Url -SkipHttpErrorCheck -TimeoutSec 20
  if ($r.StatusCode -eq 200 -and $r.Content.Length -gt 1000) { Ok ("UI 200, " + $r.Content.Length + " bytes") }
  else { Bad ("UI status " + $r.StatusCode) }
} catch { Bad ("UI tidak bisa diakses: " + $_.Exception.Message) }

# 2. API domains
$liveDomains = @()
try {
  $j = Invoke-RestMethod -Uri "$Url/api/domains" -TimeoutSec 20
  $liveDomains = @($j.domains | ForEach-Object { $_.domain })
  Ok ("API domain: " + ($liveDomains -join ", "))
} catch { Bad ("API /api/domains gagal: " + $_.Exception.Message) }

# 3. API dasar + opsional uji inbox dengan login
try {
  $h = Invoke-RestMethod -Uri "$Url/api/health" -TimeoutSec 20
  Ok ("API hidup, " + @($liveDomains).Count + " domain aktif")
} catch { Bad ("/api/health gagal: " + $_.Exception.Message) }

if ($Email -and $Password) {
  try {
    $sess = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $body = @{ email = $Email; password = $Password; captcha = $CaptchaToken } | ConvertTo-Json
    try {
      $null = Invoke-RestMethod -Uri "$Url/api/auth/login" -Method POST -ContentType "application/json" -Body $body -WebSession $sess -TimeoutSec 20
      Ok ("login " + $Email)
    } catch {
      $msg = $_.ErrorDetails.Message
      if ($msg -match "captcha_required") {
        Ok "Turnstile aktif (login butuh captcha) — uji inbox dilewati"
        return
      }
      throw
    }
    $new = Invoke-RestMethod -Uri "$Url/api/new" -Method POST -WebSession $sess -TimeoutSec 20
    $box = Invoke-RestMethod -Uri "$Url/api/inbox/$($new.address)" -WebSession $sess -TimeoutSec 20
    Ok ("inbox uji " + $new.address + " (" + @($box.messages).Count + " pesan)")
  } catch { Bad ("uji inbox dengan login gagal: " + $_.Exception.Message) }
} else {
  Skip "uji inbox dilewati (isi -Email/-Password untuk menguji)"
}

# 4. MX per domain
foreach ($d in $Domains) {
  try {
    $mx = Resolve-DnsName -Name $d -Type MX -ErrorAction Stop |
          Where-Object { $_.NameExchange } | Select-Object -ExpandProperty NameExchange
    if ($mx -and ($mx -join ",") -match "mx\.cloudflare\.net") {
      Ok ("MX $d -> " + ($mx -join ", "))
    } elseif ($mx) {
      Bad ("MX $d bukan Cloudflare: " + ($mx -join ", "))
    } else {
      Bad ("MX $d kosong (Email Routing belum aktif)")
    }
  } catch { Bad ("MX $d tidak terbaca: " + $_.Exception.Message) }
}

# 5. Cloudflare API (opsional)
if (-not $env:CLOUDFLARE_API_TOKEN) {
  Skip "CLOUDFLARE_API_TOKEN tidak ada, cek Email Routing & catch-all dilewati"
} else {
  $h = @{ Authorization = "Bearer $env:CLOUDFLARE_API_TOKEN" }
  foreach ($d in $Domains) {
    try {
      $z = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones?name=$d" -Headers $h -TimeoutSec 20
      if (-not $z.result.Count) { Bad ("zone $d tidak ada di akun"); continue }
      $zid = $z.result[0].id
      $er = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$zid/email/routing" -Headers $h -TimeoutSec 20
      if ($er.result.enabled -and $er.result.status -eq "ready") { Ok ("Email Routing $d ready") }
      else { Bad ("Email Routing ${d}: enabled=" + $er.result.enabled + " status=" + $er.result.status) }

      $ca = Invoke-RestMethod -Uri "https://api.cloudflare.com/client/v4/zones/$zid/email/routing/rules/catch_all" -Headers $h -TimeoutSec 20
      $act = $ca.result.actions[0]
      $isTempDomain = $liveDomains -contains $d
      if ($isTempDomain) {
        if ($ca.result.enabled -and $act.type -eq "worker" -and ($act.value -contains $WorkerName)) {
          Ok ("catch-all $d -> worker " + $WorkerName + " (domain temp mail)")
        } else {
          Bad ("catch-all ${d} salah: enabled=" + $ca.result.enabled + " action=" + $act.type)
        }
      } else {
        if (-not $ca.result.enabled) { Ok ("catch-all $d mati (domain utama, benar)") }
        else { Bad ("$d bukan domain temp mail tapi catch-all masih aktif") }
      }
    } catch { Bad ("cek Cloudflare $d gagal: " + $_.Exception.Message) }
  }
}

Write-Host ""
if ($fail -eq 0) { Write-Host "SEMUA CEK LULUS." -ForegroundColor Green; exit 0 }
else { Write-Host ("ADA " + $fail + " MASALAH.") -ForegroundColor Red; exit 1 }
