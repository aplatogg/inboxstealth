# deploy.ps1 — Temp Mail Multi-Domain auto-deploy
# Jalanin: klik kanan -> Run with PowerShell, ATAU
#          pwsh -File .\deploy.ps1
#
# Script ini:
#   1. cek login Cloudflare (wrangler login kalau belum)
#   2. bikin D1 database kalau belum ada
#   3. ambil database_id otomatis -> tulis ke wrangler.toml
#   4. minta domain & token admin (disimpan lokal, TIDAK dikirim ke mana2)
#   5. migrasi schema + deploy worker
#
# Semua kredensial tetap di folder ini (.env lokal + wrangler session).

$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

function Say($m) { Write-Host "[*] $m" -ForegroundColor Cyan }
function Ok($m)  { Write-Host "[+] $m" -ForegroundColor Green }
function Warn($m){ Write-Host "[!] $m" -ForegroundColor Yellow }
function Die($m) { Write-Host "[-] $m" -ForegroundColor Red; exit 1 }

Write-Host "=== Temp Mail Multi-Domain deployer ===" -ForegroundColor Magenta

# ---------- 0. cek node & wrangler ----------
if (-not (Get-Command node -ErrorAction SilentlyContinue)) { Die "Node.js belum terpasang. Install dari https://nodejs.org" }
Say ("node " + (node --version))

# ---------- 1. install deps ----------
if (-not (Test-Path -LiteralPath ".\node_modules")) {
  Say "install dependencies..."
  npm install --silent
}
Ok "dependencies siap"

# ---------- 2. login wrangler ----------
Say "cek autentikasi Cloudflare..."
if ($env:CLOUDFLARE_API_TOKEN) {
  Ok "pakai CLOUDFLARE_API_TOKEN dari environment (skip wrangler login)"
  $who = npx wrangler whoami 2>&1 | Out-String
  if ($who -notmatch "Account ID|associated with the email") {
    Die "token tidak valid / kurang permission. Cek token di dashboard Cloudflare."
  }
  Ok "token valid"
} else {
  $who = $null
  try { $who = npx wrangler whoami 2>&1 | Out-String } catch { $who = "" }
  if ($who -notmatch "associated with the email|Account ID") {
    Warn "belum login. Browser bakal kebuka buat login Cloudflare."
    npx wrangler login
  } else {
    Ok "sudah login Cloudflare"
  }
}

# ---------- 3. bikin D1 kalau belum ada ----------
Say "cek D1 database 'tempmail_db'..."
$d1list = npx wrangler d1 list 2>&1 | Out-String
$dbId = $null
if ($d1list -match "tempmail_db") {
  # ambil uuid dari baris yang mengandung tempmail_db
  foreach ($line in ($d1list -split "`n")) {
    if ($line -match "tempmail_db") {
      $m = [regex]::Match($line, "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
      if ($m.Success) { $dbId = $m.Groups[1].Value; break }
    }
  }
  Ok "D1 sudah ada: $dbId"
} else {
  Say "bikin D1 baru..."
  $out = npx wrangler d1 create tempmail_db 2>&1 | Out-String
  $m = [regex]::Match($out, "([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})")
  if (-not $m.Success) { Die "gagal baca database_id dari output. Jalanin manual: npx wrangler d1 create tempmail_db" }
  $dbId = $m.Groups[1].Value
  Ok "D1 dibuat: $dbId"
}

# ---------- 4. tulis database_id ke wrangler.toml ----------
Say "update wrangler.toml (database_id)..."
$toml = Get-Content -LiteralPath ".\wrangler.toml" -Raw
$toml = $toml -replace 'database_id = "[^"]*"', "database_id = `"$dbId`""
Set-Content -LiteralPath ".\wrangler.toml" -Value $toml -NoNewline -Encoding UTF8
Ok "wrangler.toml updated"

# ---------- 5. minta domain default ----------
Write-Host ""
$defDomain = Read-Host "Masukkan domain UTAMA temp mail (mis: kotakposku.com)"
if ([string]::IsNullOrWhiteSpace($defDomain)) { Die "domain wajib diisi" }
$defDomain = $defDomain.Trim().ToLower()

Write-Host ""
Warn "Masukkan SEMUA domain kamu, pisah koma. Contoh: kotakposku.com, mail2.xyz, inbox.net"
$allDomainsRaw = Read-Host "Daftar domain"
if ([string]::IsNullOrWhiteSpace($allDomainsRaw)) { $allDomainsRaw = $defDomain }
$allDomains = @($allDomainsRaw -split "," | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ })

Say "update DEFAULT_DOMAIN di wrangler.toml..."
$toml = Get-Content -LiteralPath ".\wrangler.toml" -Raw
$toml = $toml -replace 'DEFAULT_DOMAIN = "[^"]*"', "DEFAULT_DOMAIN = `"$defDomain`""
Set-Content -LiteralPath ".\wrangler.toml" -Value $toml -NoNewline -Encoding UTF8
Ok "default domain: $defDomain"

# ---------- 6. token admin ----------
Write-Host ""
Say "Bikin token admin acak otomatis..."
$bytes = New-Object byte[] 32
[System.Security.Cryptography.RandomNumberGenerator]::Fill($bytes)
$adminToken = -join ($bytes | ForEach-Object { "{0:x2}" -f $_ })
Ok "token admin dibuat (disimpan lokal, TIDAK dikirim ke sistem ini)"

# ---------- 7. migrasi schema + seed domain ----------
Say "migrasi schema ke D1..."
# bangun SQL seed dinamis dari daftar domain
$seedSql = @"
DELETE FROM domains;
"@
$idx = 0
foreach ($d in $allDomains) {
  $isDef = if ($d -eq $defDomain) { 1 } else { 0 }
  $label = $d.Split(".")[0]
  $seedSql += "INSERT OR IGNORE INTO domains (domain, is_active, is_default, label, created_at) VALUES ('$d', 1, $isDef, '$label', 0);`n"
  $idx++
}
$tmpSeed = Join-Path $PSScriptRoot "_seed_domains.sql"
Set-Content -LiteralPath $tmpSeed -Value $seedSql -Encoding UTF8

npx wrangler d1 execute tempmail_db --file=./schema.sql --remote
npx wrangler d1 execute tempmail_db --file=./_seed_domains.sql --remote
Remove-Item -LiteralPath $tmpSeed -Force -ErrorAction SilentlyContinue
Ok "schema + $idx domain terdaftar"

# ---------- 8. set secret ADMIN_TOKEN ----------
Say "set ADMIN_TOKEN sebagai secret worker..."
$adminToken | npx wrangler secret put ADMIN_TOKEN
Ok "secret tersimpan"

# ---------- 9. deploy worker ----------
Say "deploy worker..."
npx wrangler deploy

# ---------- 10. simpan info lokal ----------
$infoPath = Join-Path $PSScriptRoot "DEPLOY-INFO.txt"
@"
Temp Mail sudah di-deploy.
================================
Default domain : $defDomain
Domain terdaftar:
$($allDomains | ForEach-Object { "  - $_" } | Out-String)
D1 database id : $dbId
ADMIN_TOKEN    : $adminToken

SIMPAN FILE INI. Jangan upload/commit.
Untuk aktifkan email masuk, di Cloudflare Dashboard tiap domain:
  Email -> Email Routing -> Enable
  Routing rules -> Catch-all -> Send to a Worker -> tempmail
"@ | Set-Content -LiteralPath $infoPath -Encoding UTF8

Write-Host ""
Ok "SELESAI."
Write-Host "Info login/setup ada di: $infoPath" -ForegroundColor Yellow
Write-Host ""
Warn "LANGKAH MANUAL (sekali per domain) di Cloudflare Dashboard:"
Write-Host "  domain -> Email -> Email Routing -> Enable"
Write-Host "  Routing rules -> Catch-all address -> Send to a Worker -> pilih 'tempmail'"
Write-Host ""
Write-Host ("Buka: https://" + $defDomain) -ForegroundColor Green
