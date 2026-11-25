# add-domain.ps1 — daftarkan domain baru sebagai domain temp mail.
#
# Pakai:
#   $env:CLOUDFLARE_API_TOKEN = "..."      # token dengan Zone:Edit + Email Routing:Edit + D1:Edit
#   pwsh -File .\add-domain.ps1 -Domain contoh.id
#
# Alur:
#   1. kalau zone belum ada -> dibuat, lalu cetak 2 nameserver untuk dipasang di registrar
#   2. kalau zone sudah ada tapi pending -> cetak NS yang harus dipasang
#   3. kalau zone active -> bersihkan MX lama, aktifkan Email Routing, arahkan catch-all
#      ke worker `tempmail`, lalu masukkan domain ke tabel domains di D1

param(
  [Parameter(Mandatory = $true)][string]$Domain,
  [string]$Label = "",
  [string]$WorkerName = "tempmail",
  [string]$D1Name = "tempmail_db",
  [switch]$MakeDefault,
  [switch]$Premium
)

$ErrorActionPreference = "Stop"
function Ok($m)   { Write-Host "[ok]   $m" -ForegroundColor Green }
function Info($m) { Write-Host "[info] $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[!]    $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host "[-]    $m" -ForegroundColor Red; exit 1 }

if (-not $env:CLOUDFLARE_API_TOKEN) { Die "set CLOUDFLARE_API_TOKEN dulu" }
$Domain = $Domain.Trim().ToLower()
$h = @{ Authorization = "Bearer $env:CLOUDFLARE_API_TOKEN" }
$api = "https://api.cloudflare.com/client/v4"

Write-Host "domain: $Domain" -ForegroundColor Magenta

# ---------- 1. zone ----------
$z = Invoke-RestMethod -Uri "$api/zones?name=$Domain" -Headers $h
if (-not $z.result.Count) {
  Info "zone belum ada, membuat..."
  $acct = $env:CLOUDFLARE_ACCOUNT_ID
  if (-not $acct) {
    $who = Invoke-RestMethod -Uri "$api/accounts" -Headers $h
    $acct = $who.result[0].id
  }
  $body = @{ name = $Domain; type = "full"; account = @{ id = $acct } } | ConvertTo-Json
  $c = Invoke-RestMethod -Uri "$api/zones" -Method POST -Headers $h -ContentType "application/json" -Body $body
  $zid = $c.result.id
  Start-Sleep -Seconds 2
  $z = Invoke-RestMethod -Uri "$api/zones/$zid" -Headers $h
}

$zid = $z.result[0].id
$status = $z.result[0].status
$ns = $z.result[0].name_servers
Info "zone id: $zid · status: $status"

if ($status -ne "active") {
  Warn "zone belum aktif. Pasang 2 nameserver ini di registrar, lalu jalankan script lagi:"
  $ns | ForEach-Object { Write-Host ("       " + $_) -ForegroundColor Yellow }
  exit 2
}
Ok "zone active"

# ---------- 2. MX lama yang bukan Cloudflare ----------
$dns = Invoke-RestMethod -Uri "$api/zones/$zid/dns_records?type=MX&per_page=100" -Headers $h
$bad = @($dns.result | Where-Object { $_.content -notlike "*mx.cloudflare.net" })
foreach ($r in $bad) {
  $null = Invoke-RestMethod -Uri "$api/zones/$zid/dns_records/$($r.id)" -Method DELETE -Headers $h
  Warn ("hapus MX lama: " + $r.content)
}

# ---------- 3. Email Routing ----------
try {
  $er = Invoke-RestMethod -Uri "$api/zones/$zid/email/routing" -Headers $h
  if (-not $er.result.enabled) {
    $null = Invoke-RestMethod -Uri "$api/zones/$zid/email/routing/enable" -Method POST -Headers $h -ContentType "application/json" -Body "{}"
  }
} catch {
  Warn ("enable Email Routing gagal: " + $_.Exception.Message)
}

Start-Sleep -Seconds 2
$er = Invoke-RestMethod -Uri "$api/zones/$zid/email/routing" -Headers $h
if ($er.result.errors) {
  foreach ($e in $er.result.errors) {
    if ($e.code -eq "spf.foreign") {
      $txt = Invoke-RestMethod -Uri "$api/zones/$zid/dns_records?type=TXT&per_page=100" -Headers $h
      foreach ($rec in $txt.result) {
        if ($rec.content -like "*spf*") {
          $b = @{ type = "TXT"; name = $Domain; content = "v=spf1 include:_spf.mx.cloudflare.net ~all"; ttl = 1 } | ConvertTo-Json
          $null = Invoke-RestMethod -Uri "$api/zones/$zid/dns_records/$($rec.id)" -Method PATCH -Headers $h -ContentType "application/json" -Body $b
          Warn "SPF diganti ke Cloudflare"
        }
      }
      Start-Sleep -Seconds 2
      $er = Invoke-RestMethod -Uri "$api/zones/$zid/email/routing" -Headers $h
    }
  }
}
if ($er.result.enabled -and $er.result.status -eq "ready") { Ok "Email Routing ready" }
else { Warn ("Email Routing status: " + $er.result.status) }

# ---------- 4. catch-all -> worker ----------
$body = @{
  name = "catch-all to $WorkerName"; enabled = $true
  matchers = @(@{ type = "all" })
  actions  = @(@{ type = "worker"; value = @($WorkerName) })
} | ConvertTo-Json -Depth 5
$ca = Invoke-RestMethod -Uri "$api/zones/$zid/email/routing/rules/catch_all" -Method PUT -Headers $h -ContentType "application/json" -Body $body
if ($ca.success) { Ok "catch-all -> worker $WorkerName" } else { Die "gagal set catch-all" }

# ---------- 5. daftarkan di D1 ----------
$isDef = if ($MakeDefault) { 1 } else { 0 }
if ($MakeDefault) {
  $null = & npx wrangler d1 execute $D1Name --command="UPDATE domains SET is_default = 0;" --remote 2>&1
}
$lbl = if ($Label) { $Label } else { $Domain.Split(".")[0] }
$isPrem = if ($Premium) { 1 } else { 0 }
$sql = "INSERT INTO domains (domain,is_active,is_default,label,is_premium,created_at) VALUES ('$Domain',1,$isDef,'$lbl',$isPrem,0) " +
       "ON CONFLICT(domain) DO UPDATE SET is_active=1, is_default=$isDef, is_premium=$isPrem;"
$out = & npx wrangler d1 execute $D1Name --command="$sql" --remote 2>&1 | Out-String
if ($out -match "Executed|success") { Ok "terdaftar di D1 (label: $lbl, default: $([bool]$MakeDefault), premium: $([bool]$Premium))" }
else { Warn "gagal daftar D1: $out" }

Write-Host ""
Ok "SELESAI. Domain $Domain siap dipakai di menu Inbox."
