// src/app-shell.js — Authenticated dashboard HTML shell (served only after /api/auth/me = 200)
export const APP_SHELL_HTML = `
<div class="app" id="appShell" hidden>
  <aside class="sidebar">
    <div class="brand">
      <svg width="20" height="20" viewBox="0 0 20 20" fill="none" aria-hidden="true">
        <path d="M2.5 5.5h15v9h-15z" stroke="currentColor" stroke-width="1.4"/>
        <path d="M2.5 6.2 10 11l7.5-4.8" stroke="currentColor" stroke-width="1.4"/>
      </svg>
      <div>
        <div class="brand-name">menyurat</div>
        <div class="brand-sub">inbox sementara</div>
      </div>
    </div>

    <nav aria-label="Navigasi utama">
      <a class="nav-item" href="#/inbox" data-nav="inbox">Inbox <span class="n" id="navCount">0</span></a>
      <a class="nav-item" href="#/addresses" data-nav="addresses">Alamat <span class="n" id="navAddr">0</span></a>
      <a class="nav-item" href="#/matrix" data-nav="matrix">Matrix <span class="n" id="navMatrix">0</span></a>
      <a class="nav-item" href="#/domains" data-nav="domains">Domain <span class="n" id="navDomains">0</span></a>
      <a class="nav-item" href="#/dashboard" data-nav="dashboard" id="navDash" hidden>Ringkasan</a>
      <a class="nav-item" href="#/audit" data-nav="audit" id="navAudit" hidden>Log</a>
      <a class="nav-item" href="#/users" data-nav="users" id="navUsers" hidden>
        Pengguna <span class="n" id="navPending">0</span>
      </a>
    </nav>

    <div class="sidebar-foot">
      <div class="ttl-card">
        <div class="k" id="ttlK">Belum ada alamat aktif</div>
        <div class="v mono" id="ttlV">—</div>
      </div>
      <div style="font-size:11.5px;color:var(--muted);padding:4px 6px 0;display:flex;gap:8px;flex-wrap:wrap">
        <a href="/privacy" style="color:var(--muted);text-decoration:none">Privasi</a>
        <span>·</span>
        <a href="/terms" style="color:var(--muted);text-decoration:none">Ketentuan</a>
      </div>
    </div>
  </aside>

  <header class="topbar">
    <button class="menu-btn" id="menuBtn" aria-label="Buka menu">Menu</button>
    <div class="search">
      <svg width="14" height="14" viewBox="0 0 16 16" fill="none" aria-hidden="true">
        <circle cx="6.8" cy="6.8" r="4.4" stroke="currentColor" stroke-width="1.3"/>
        <path d="m10.4 10.4 3 3" stroke="currentColor" stroke-width="1.3"/>
      </svg>
      <input id="searchInput" type="search" placeholder="Cari pengirim atau subjek" aria-label="Cari pesan">
    </div>
    <button class="btn btn-quiet" id="refreshBtn">Muat ulang</button>

    <div class="acct" id="acctWrap">
      <button class="acct-btn" id="acctBtn" aria-haspopup="menu" aria-expanded="false" aria-controls="acctMenu">
        <span class="avatar" id="acctInitial">?</span>
        <span class="acct-email" id="acctEmail">—</span>
        <svg class="chev" width="12" height="12" viewBox="0 0 12 12" fill="none" aria-hidden="true">
          <path d="m3 4.5 3 3 3-3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
        </svg>
      </button>
      <div class="acct-menu" id="acctMenu" role="menu" hidden>
        <div class="acct-head">
          <span class="avatar big" id="acctInitial2">?</span>
          <div class="who">
            <b id="acctName">—</b>
            <span id="acctMail">—</span>
          </div>
        </div>
        <span class="acct-role" id="acctRole"></span>
        <div class="acct-sep"></div>
        <button class="acct-item" id="acctTheme" role="menuitem">Mode gelap <span class="sw"><input type="checkbox" id="themeToggle" tabindex="-1" aria-label="Mode gelap"></span></button>
        <button class="acct-item" id="acctSettings" role="menuitem">Pengaturan akun</button>
        <button class="acct-item danger" id="acctLogout" role="menuitem">Keluar</button>
      </div>
    </div>
  </header>

  <main class="sheet">
    <div class="banner" id="banner" hidden></div>
    <div class="title-row">
      <div>
        <h1 id="pageTitle">Inbox</h1>
        <p class="sub" id="pageSub">Belum ada alamat aktif.</p>
      </div>
      <div class="title-actions">
        <button class="btn" id="qrTop" hidden>QR</button>
        <button class="btn" id="exportTop" hidden>Ekspor</button>
        <button class="btn" id="copyTop">Salin alamat</button>
        <button class="btn btn-primary" id="newTop">Alamat baru</button>
      </div>
    </div>

    <section id="inboxView">
      <div class="address-strip" id="addressStrip" hidden>
        <div class="addr">
          <b id="addrText">—</b>
          <details class="rowmenu addr-switcher" id="addrSwitchWrap" hidden>
            <summary class="btn btn-sm addr-switch-btn" title="Ganti alamat aktif dengan cepat" aria-label="Ganti alamat aktif">
              <span>Ganti</span>
              <svg width="11" height="11" viewBox="0 0 12 12" fill="none" aria-hidden="true"><path d="m3 4.5 3 3 3-3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/></svg>
            </summary>
            <div class="menu-pop addr-switch-pop" id="addrSwitchList"></div>
          </details>
          <span class="chip" id="addrDomain">—</span>
          <span class="chip note-chip" id="addrNoteChip" hidden></span>
          <span class="live-pill" id="sseLiveBadge" data-live="false" title="Status pantauan email masuk realtime"><span class="live-dot"></span><span id="sseLiveText">Live</span></span>
        </div>
        <div class="addr-actions">
          <span class="ttl" id="ttlInline">—</span>
          <button class="btn" id="copyBtn">Salin</button>
          <button class="btn" id="noteBtn" title="Catatan / label alamat">Label</button>
          <button class="btn" id="openMatrixBtn" title="Buka &amp; kelola alamat ini di Account Matrix">⚡ Matrix</button>
          <button class="btn" id="qrBtn">QR</button>
          <button class="btn" id="exportBtn">Ekspor</button>
        </div>
      </div>

      <div class="setup" id="setupBox">
        <div class="setup-grid">
          <section class="panel">
            <h2 class="panel-title">Buat alamat</h2>
            <div class="field">
              <label for="localInput">Nama alamat</label>
              <div class="row-input">
                <input id="localInput" placeholder="kosongkan untuk acak" maxlength="64" autocomplete="off">
                <select id="domainSelect" aria-label="Domain"></select>
                <button class="btn btn-primary" id="createBtn">Buat alamat</button>
                <span class="hint" id="premHint" hidden>Domain bertanda premium hanya untuk VIP ke atas.</span>
              </div>
              <span class="hint">Kosongkan nama untuk alamat acak.</span>
            </div>
            <div class="field" id="setupTtlWrap" hidden>
              <label for="setupTtl">Masa aktif</label>
              <select id="setupTtl">
                <option value="3600">1 jam</option>
                <option value="86400">1 hari</option>
                <option value="259200">3 hari</option>
                <option value="604800">7 hari</option>
                <option value="1209600" selected>14 hari</option>
                <option value="2592000">30 hari</option>
                <option value="7776000">90 hari</option>
              </select>
              <span class="hint">VIP/admin sampai 90 hari; owner sampai 365 hari; member 7 hari.</span>
            </div>
            <div class="preview">
              <span class="k">Alamat yang akan dibuat</span>
              <b class="mono" id="previewAddr">nama@domain</b>
            </div>
          </section>

          <section class="panel">
            <h2 class="panel-title">Cara kerja</h2>
            <ol class="steps">
              <li>Pilih domain yang sudah terdaftar, lalu tentukan nama alamat atau biarkan acak.</li>
              <li>Pakai alamat itu saat mendaftar di situs lain. Email masuk muncul di sini dalam beberapa detik.</li>
              <li>Saat masa aktif habis, alamat dan seluruh isinya dihapus otomatis.</li>
            </ol>
            <div class="domain-rows" id="domainRows"></div>
          </section>

          <section class="panel panel-wide">
            <h2 class="panel-title">Domain terdaftar</h2>
            <div class="dtable" id="domainTable"></div>
          </section>

          <section class="panel panel-wide">
            <h2 class="panel-title">Batas layanan</h2>
            <div class="limits">
              <div><span class="k">Masa berlaku alamat</span> <span class="v" id="ttlInfo">sesuai peran</span></div>
              <div><span class="k">Ukuran email maksimum</span> <span class="v">15 MB (arsip .eml hanya untuk pesan &lt;=6 MB)</span></div>
              <div><span class="k">Pembersihan otomatis</span> <span class="v">tiap 10 menit</span></div>
              <div><span class="k">Pesan ditampilkan</span> <span class="v">200 terbaru per alamat</span></div>
            </div>
            <p class="note" style="margin-top:14px">Endpoint API (butuh login / API key): <span class="mono">/api/new</span>, <span class="mono">/api/custom</span>, <span class="mono">/api/inbox/:alamat</span>.</p>
          </section>
        </div>
      </div>

      <div class="inbox" id="inboxBody" hidden>
        <div class="list-col" id="listCol">
          <div class="mobile-search">
            <input id="mobileSearchInput" type="search" placeholder="Cari pengirim atau subjek…" aria-label="Cari pesan">
          </div>
          <div class="list-toolbar" role="tablist" aria-label="Filter pesan">
            <button class="tab" role="tab" id="tabAll" aria-selected="true">Semua</button>
            <button class="tab" role="tab" id="tabUnread" aria-selected="false">Belum dibaca</button>
            <span class="list-count" id="listCount">0 pesan</span>
            <button class="btn btn-sm" id="markAllReadBtn" type="button" title="Tandai semua pesan sudah dibaca" hidden>Baca semua</button>
            <button class="btn btn-sm" id="clearMsgsBtn" type="button" title="Kosongkan semua pesan di alamat ini" hidden>Kosongkan</button>
          </div>
          <ul class="msg-list" id="msgList"></ul>
        </div>
        <div class="read-col" id="readCol">
          <div class="read-empty" id="readEmpty">
            <h2>Belum ada pesan dibuka</h2>
            <p>Pilih satu pesan di kolom kiri. Email yang masuk ke alamat aktif muncul di daftar itu dalam beberapa detik.</p>
          </div>
        </div>
      </div>
    </section>

    <section id="domainsView" hidden>
      <div class="panel" id="domainForm" hidden>
        <h2 class="panel-title">Tambah domain</h2>
        <div class="row-input">
          <input id="ndDomain" placeholder="contoh.id" autocomplete="off" aria-label="Domain">
          <input id="ndLabel" placeholder="label (opsional)" style="flex:0 1 200px" aria-label="Label">
          <button class="btn btn-primary" id="ndBtn">Tambah</button>
        </div>
        <span class="hint" style="display:block;margin-top:10px">Domain harus aktif di Cloudflare dengan catch-all ke worker ini.</span>
        <div class="auth-msg" id="ndMsg" hidden></div>
      </div>

      <div class="cards" id="domainCards"></div>

      <div class="panel" id="domainAdmin" hidden style="margin-top:24px">
        <h2 class="panel-title">Kelola domain</h2>
        <div class="dtable" id="adminDomainRows"></div>
      </div>

      <p class="note">Semua domain diarahkan catch-all ke worker yang sama. Owner/admin bisa menambah atau menonaktifkan domain lewat <span class="mono">/api/admin/domains</span>.</p>
    </section>

    <section id="usersView" hidden>
      <div class="list-toolbar" role="tablist" aria-label="Filter pengguna">
        <button class="tab" role="tab" id="uAll" aria-selected="true">Semua</button>
        <button class="tab" role="tab" id="uPending" aria-selected="false">Menunggu</button>
        <button class="tab" role="tab" id="uApproved" aria-selected="false">Disetujui</button>
        <span class="list-count" id="uCount">0</span>
      </div>
      <div id="resetQueue"></div>
      <div class="utable" id="userTable"></div>

      <div class="panel" style="margin-top:24px">
        <h2 class="panel-title">Buat akun tanpa registrasi</h2>
        <div class="row-input">
          <input id="cuEmail" type="email" placeholder="email" autocomplete="off" aria-label="Email">
          <input id="cuName" type="text" placeholder="nama (opsional)" maxlength="60" style="flex:0 1 180px" aria-label="Nama">
          <input id="cuPass" type="text" placeholder="kata sandi min 8" autocomplete="off" style="flex:0 1 180px" aria-label="Kata sandi">
          <select id="cuRole" aria-label="Role"></select>
          <button class="btn btn-primary" id="cuBtn">Buat akun</button>
        </div>
        <span class="hint" style="display:block;margin-top:10px">Akun langsung aktif tanpa approval. Hanya owner yang bisa membuat admin.</span>
        <div class="auth-msg" id="cuMsg" hidden></div>
      </div>
    </section>

    <section id="addressesView" hidden>
      <div class="searchaddr">
        <input id="addrSearch" type="search" placeholder="Cari alamat" aria-label="Cari alamat">
        <label class="selall"><input type="checkbox" id="selAll"> Pilih semua</label>
      </div>
      <div class="bulkbar" id="bulkBar" hidden>
        <span class="n" id="bulkCount">0 dipilih</span>
        <button class="btn btn-sm" id="bulkExtend">Perpanjang</button>
        <button class="btn btn-sm" id="bulkPin">Simpan</button>
        <button class="btn btn-sm" id="bulkUnpin">Lepas</button>
        <span class="sp"></span>
        <button class="btn btn-sm" id="bulkExport">Ekspor</button>
        <button class="btn btn-sm" id="bulkDel">Hapus</button>
      </div>
      <div class="alist" id="addressRows"></div>
      <p class="note">Masa aktif mengikuti peran: member 7 hari; VIP dan admin bebas sampai 90 hari; owner sampai 365 hari. Semua isi alamat ikut terhapus saat kedaluwarsa.</p>
    </section>

    <section id="matrixView" hidden>
      <div class="panel">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:10px;flex-wrap:wrap;margin-bottom:4px">
          <h2 class="panel-title" style="margin:0">⚡ 1-Click Auto-Spawn &amp; Auto-Detected Vault</h2>
          <span class="chip ok">Otomatis mendeteksi layanan dari setiap email masuk</span>
        </div>
        <p class="hint" style="margin:0 0 8px">Klik salah satu tombol layanan di bawah untuk langsung membuat email permanen + username + password 18-karakter dalam 1 klik (tanpa ketik manual), atau biarkan sistem mendeteksi otomatis saat ada email verifikasi masuk.</p>

        <div class="mx-presets" id="mxPresetBar">
          <span class="mx-presets-lbl">1-Klik Instan:</span>
          <button type="button" class="mx-preset-btn" data-mx-quick="Auto-Detect" data-mx-days="0" title="Buat email + password sekarang, nama layanan otomatis terdeteksi saat email pertama masuk">🔍 + Auto-Detect (Bebas)</button>
          <button type="button" class="mx-preset-btn" data-mx-quick="Claude (Anthropic)" data-mx-days="0">⚡ + Claude</button>
          <button type="button" class="mx-preset-btn" data-mx-quick="OpenAI" data-mx-days="0">⚡ + OpenAI</button>
          <button type="button" class="mx-preset-btn" data-mx-quick="Cursor" data-mx-days="14">⚡ + Cursor (14d)</button>
          <button type="button" class="mx-preset-btn" data-mx-quick="Mistral AI" data-mx-days="0">⚡ + Mistral AI</button>
          <button type="button" class="mx-preset-btn" data-mx-quick="AWS" data-mx-days="0">⚡ + AWS</button>
          <button type="button" class="mx-preset-btn" data-mx-quick="Qwen AI" data-mx-days="0">⚡ + Qwen AI</button>
          <button type="button" class="mx-preset-btn" data-mx-quick="GitHub" data-mx-days="0">⚡ + GitHub</button>
          <button type="button" class="mx-preset-btn" data-mx-quick="Steam" data-mx-days="0">⚡ + Steam</button>
          <button type="button" class="mx-preset-btn" data-mx-quick="Vercel" data-mx-days="0">⚡ + Vercel</button>
          <button type="button" class="mx-preset-btn" data-mx-quick="Supabase" data-mx-days="0">⚡ + Supabase</button>
        </div>

        <div class="mx-grid-form" style="grid-template-columns:minmax(150px,1fr) minmax(140px,1fr) minmax(180px,1.4fr) auto">
          <select id="mxDomain" aria-label="Domain email"></select>
          <select id="mxTrial" aria-label="Masa aktif / trial">
            <option value="0">Permanen (Active)</option>
            <option value="3">Trial 3 hari</option>
            <option value="7">Trial 7 hari</option>
            <option value="14">Trial 14 hari</option>
            <option value="30">Trial 30 hari</option>
            <option value="90">Trial 90 hari</option>
          </select>
          <input id="mxService" placeholder="Ketik judul sendiri / web baru (kosongkan = Auto-Detect)…" maxlength="60" autocomplete="off" aria-label="Layanan">
          <button class="btn btn-primary" id="mxSpawnBtn" type="button" style="height:36px;padding:0 16px">⚡ Spawn Akun</button>
        </div>

        <details class="mx-adv">
          <summary>⚙️ Opsi Kustom / Input Manual (Tag, Nama Email, Username, Password, 2FA TOTP, Catatan OPSEC)</summary>
          <div class="mx-grid-form" style="margin-top:8px">
            <input id="mxTag" placeholder="Tag (mis. #Alt-01, #Trial)" maxlength="40" autocomplete="off" aria-label="Tag">
            <input id="mxLocal" placeholder="Nama email (kosong = acak natural)" maxlength="64" autocomplete="off" aria-label="Nama lokal email">
            <input id="mxUser" placeholder="Username (kosong = otomatis)" maxlength="80" autocomplete="off" aria-label="Username">
            <input id="mxPass" placeholder="Password (kosong = auto 18-char kuat)" maxlength="200" autocomplete="off" aria-label="Password">
            <input id="mxTotp" placeholder="2FA TOTP Secret / otpauth:// (opsional)" maxlength="200" autocomplete="off" aria-label="2FA TOTP Secret">
            <input id="mxOpsec" placeholder="Catatan OPSEC (mis. Brave #3 · Proxy SG)" maxlength="300" autocomplete="off" aria-label="Catatan OPSEC">
          </div>
        </details>
        <div class="auth-msg" id="mxSpawnMsg" hidden></div>
      </div>

      <div class="searchaddr" style="margin-top:16px">
        <input id="mxSearch" type="search" placeholder="Cari layanan, tag, email, username, atau catatan OPSEC…" aria-label="Cari di Matrix">
        <div class="mx-filter-pills" id="mxFilterPills" role="group" aria-label="Filter status akun"></div>
        <span style="flex:1 1 auto"></span>
        <button class="btn" id="mxSyncBtn" type="button" style="height:34px" title="Pindai semua inbox &amp; email masuk untuk mendeteksi akun secara otomatis">⚡ Auto-Sync dari Inbox</button>
        <button class="btn" id="mxRefreshAllBtn" type="button" style="height:34px">🔄 Refresh OTP</button>
        <details class="rowmenu">
          <summary class="btn" style="height:34px">📥 Export Vault</summary>
          <div class="menu-pop">
            <button type="button" class="menu-item" id="mxExportJson">Export JSON (Full Vault)</button>
            <button type="button" class="menu-item" id="mxExportCsv">Export CSV (Bitwarden / KeePass)</button>
          </div>
        </details>
      </div>

      <div class="mx-list" id="matrixRows"></div>
    </section>

    <section id="accountView" hidden>
      <div class="panel">
        <h2 class="panel-title">Kunci API</h2>
        <div class="row-input">
          <input id="keyName" placeholder="nama kunci, mis. cli" autocomplete="off" aria-label="Nama kunci">
          <button class="btn btn-primary" id="keyBtn">Buat kunci</button>
        </div>
        <p class="hint" style="margin:10px 0 0">Pakai lewat <span class="mono">x-api-key: mn_...</span> atau <span class="mono">Authorization: Bearer mn_...</span>. Maksimal 5 kunci aktif.</p>
        <div class="dtable" id="keyList" style="margin-top:14px"></div>
        <div class="auth-msg" id="keyMsg" hidden></div>
      </div>

      <div class="panel" style="margin-top:24px">
        <h2 class="panel-title">Ganti kata sandi</h2>
        <div class="row-input">
          <input id="pwCurrent" type="password" placeholder="sandi sekarang" autocomplete="current-password" aria-label="Sandi sekarang">
          <input id="pwNext" type="password" placeholder="sandi baru, min 8" autocomplete="new-password" aria-label="Sandi baru">
          <button class="btn" id="pwBtn">Simpan</button>
        </div>
        <div class="auth-msg" id="pwMsg" hidden></div>
      </div>

      <div class="panel" style="margin-top:24px">
        <h2 class="panel-title">Verifikasi dua langkah <span class="chip" id="totpChip">nonaktif</span></h2>
        <p class="hint" id="totpHint">Opsional. Kalau aktif, login butuh kode 6 digit dari aplikasi authenticator.</p>

        <div id="totpOff">
          <button class="btn" id="totpStart">Aktifkan</button>
        </div>

        <div id="totpSetup" hidden>
          <p class="hint">Pindai QR code ini atau tambahkan secret ke Google Authenticator / Aegis / 1Password, lalu masukkan kode 6 digitnya.</p>
          <div class="qrbox" id="totpQrWrap" hidden style="margin:12px auto"><img id="totpQrImg" alt="QR 2FA TOTP" style="width:180px;height:180px"></div>
          <div class="preview"><span class="k">Secret (klik untuk salin)</span><b class="mono" id="totpSecret" style="cursor:pointer" title="Klik untuk menyalin secret">—</b></div>
          <div class="row-input" style="margin-top:12px">
            <input id="totpCode" placeholder="kode 6 digit" maxlength="6" inputmode="numeric" autocomplete="one-time-code">
            <button class="btn btn-primary" id="totpEnable">Verifikasi &amp; aktifkan</button>
          </div>
          <div class="auth-msg" id="totpMsg" hidden></div>
        </div>

        <div id="totpOn" hidden>
          <div class="preview"><span class="k">Kode cadangan tersisa</span><b id="totpLeft">0</b></div>
          <div class="row-input" style="margin-top:12px">
            <input id="totpPass" type="password" placeholder="sandi untuk menonaktifkan" autocomplete="current-password">
            <button class="btn" id="totpDisable">Nonaktifkan</button>
          </div>
          <div class="auth-msg" id="totpMsg2" hidden></div>
        </div>

        <div id="totpCodes" hidden style="margin-top:12px">
          <p class="hint">Kode cadangan (hanya tampil sekali, simpan sekarang):</p>
          <pre class="mono" id="totpCodesList" style="white-space:pre-wrap;margin:0"></pre>
        </div>
      </div>

      <div class="panel" style="margin-top:24px">
        <h2 class="panel-title">Notifikasi suara &amp; desktop</h2>
        <p class="hint">Bunyi dan pop-up browser saat email baru masuk (otomatis menampilkan kode OTP jika terdeteksi). Suara kustom disimpan di browser ini.</p>

        <div class="row-input" style="margin-top:12px">
          <label class="switch" for="nsEnabled" style="height:38px">
            <input type="checkbox" id="nsEnabled"> Suara aktif
          </label>
          <select id="nsSound" aria-label="Suara notifikasi">
            <option value="ding">Ding</option>
            <option value="chime">Chime</option>
            <option value="pop">Pop</option>
            <option value="bell">Bell</option>
            <option value="custom">Kustom</option>
          </select>
          <label class="switch" for="nsDesktop" style="height:38px">
            <input type="checkbox" id="nsDesktop"> Pop-up desktop
          </label>
          <label class="switch" for="nsAutoOtp" style="height:38px" title="Otomatis menyalin kode OTP ke clipboard saat email baru masuk">
            <input type="checkbox" id="nsAutoOtp"> Auto-salin OTP
          </label>
        </div>

        <div class="row-input" style="margin-top:10px">
          <button class="btn" id="nsTest" type="button">Coba suara</button>
          <button class="btn" id="nsDeskTest" type="button">Coba pop-up</button>
          <button class="btn" id="nsUploadBtn" type="button">Upload audio</button>
          <input id="nsFile" type="file" accept="audio/*,.mp3,.wav,.ogg,.m4a,.aac,.opus,.flac,.webm" hidden>
          <button class="btn btn-quiet" id="nsReset" type="button">Hapus kustom</button>
        </div>

        <p class="hint" id="nsCustomInfo" hidden style="margin:10px 0 0"></p>
        <div class="auth-msg" id="nsMsg" hidden></div>
      </div>
    </section>

    <section id="dashboardView" hidden>
      <div class="panel">
        <h2 class="panel-title">Statistik</h2>
        <div class="statgrid" id="statGrid"></div>
        <div class="bars" id="statsBars"></div>
        <div class="legend"><span><i style="background:var(--accent)"></i>inbox baru</span><span><i style="background:var(--positive)"></i>email masuk</span></div>
      </div>
      <div class="panel panel-wide" style="margin-top:24px">
        <h2 class="panel-title">Domain teratas</h2>
        <div class="dtable" id="statsDomains"></div>
      </div>
      <div class="panel" style="margin-top:24px">
        <h2 class="panel-title">Pengumuman</h2>
        <p class="hint">Banner tampil di atas halaman untuk semua pengguna yang sudah masuk. Hanya satu pengumuman aktif pada satu waktu.</p>
        <div class="row-input" style="margin-top:12px">
          <input id="annText" placeholder="isi pengumuman, maks 300 karakter" maxlength="300" aria-label="Isi pengumuman">
          <select id="annLevel" aria-label="Level">
            <option value="info">Info</option>
            <option value="warning">Peringatan</option>
            <option value="critical">Penting</option>
          </select>
          <button class="btn btn-primary" id="annBtn">Tampilkan</button>
        </div>
        <div id="annList" style="margin-top:14px"></div>
        <div class="auth-msg" id="annMsg" hidden></div>
      </div>
    </section>

    <section id="auditView" hidden>
      <div class="dtable" id="auditRows"></div>
    </section>
  </main>
</div>

<dialog class="dlg" id="logDlg">
  <h2>Log alamat</h2>
  <p class="sub mono" id="logAddr">-</p>
  <div class="alist" id="logRows" style="max-height:52vh;overflow:auto"></div>
  <div class="row-actions"><button type="button" class="btn" id="logClose">Tutup</button></div>
</dialog>

<dialog class="dlg" id="ttlDlg">
  <h2>Perpanjang masa aktif</h2>
  <p class="sub mono" id="ttlAddr">-</p>
  <div class="field" id="ttlPickWrap">
    <label for="ttlPick">Masa aktif baru</label>
    <select id="ttlPick">
      <option value="3600">1 jam</option>
      <option value="86400">1 hari</option>
      <option value="259200">3 hari</option>
      <option value="604800">7 hari</option>
      <option value="1209600">14 hari</option>
      <option value="2592000">30 hari</option>
      <option value="7776000">90 hari</option>
    </select>
  </div>
  <p class="hint" id="ttlHint"></p>
  <div class="row-actions">
    <button type="button" class="btn" id="ttlCancel">Batal</button>
    <button type="button" class="btn btn-primary" id="ttlApply">Perpanjang</button>
  </div>
</dialog>

<dialog class="dlg" id="newAddrDlg">
  <form method="dialog" id="newAddrForm">
    <h2>Alamat baru</h2>
    <p class="sub">Kosongkan nama untuk alamat acak. Boleh huruf, angka, dan titik.</p>
    <div class="field">
      <label for="dlgLocal">Nama alamat</label>
      <div class="row-input">
        <input id="dlgLocal" placeholder="mis. roro.janeru" maxlength="64" autocomplete="off">
        <select id="dlgDomain" aria-label="Domain"></select>
      </div>
      <span class="hint">3-64 karakter, tidak diawali/diakhiri titik, tanpa titik ganda.</span>
    </div>
    <div class="field">
      <label for="dlgNote">Label / catatan singkat (opsional)</label>
      <input id="dlgNote" placeholder="mis. Akun Netflix, GitHub Trial" maxlength="120" autocomplete="off">
    </div>
    <div class="field" id="dlgTtlWrap" hidden>
      <label for="dlgTtl">Masa aktif</label>
      <select id="dlgTtl">
        <option value="3600">1 jam</option>
        <option value="86400">1 hari</option>
        <option value="259200">3 hari</option>
        <option value="604800">7 hari</option>
        <option value="1209600" selected>14 hari</option>
        <option value="2592000">30 hari</option>
        <option value="7776000">90 hari</option>
      </select>
      <span class="hint">VIP/admin sampai 90 hari; owner sampai 365 hari.</span>
    </div>
    <div class="preview">
      <span class="k">Alamat</span>
      <b class="mono" id="dlgPreview">—</b>
    </div>
    <div class="row-actions">
      <button type="button" class="btn" id="dlgCancel">Batal</button>
      <button type="submit" class="btn btn-primary" id="dlgCreate">Buat alamat</button>
    </div>
    <div class="auth-msg" id="dlgMsg" hidden></div>
  </form>
</dialog>

<dialog class="dlg" id="userInboxDlg" style="width:min(680px,94vw)">
  <h2 id="uiTitle">Inbox pengguna</h2>
  <p class="sub" id="uiSub">—</p>
  <div class="dtable" id="uiRows"></div>
  <div class="row-actions"><button type="button" class="btn" id="uiClose">Tutup</button></div>
</dialog>

<dialog class="dlg" id="qrDlg">
  <h2>QR alamat</h2>
  <p class="sub mono" id="qrAddr">—</p>
  <div class="qrbox"><img id="qrImg" alt="QR alamat"></div>
  <p class="qrlink mono" id="qrLink"></p>
  <div class="row-actions"><button type="button" class="btn" id="qrClose">Tutup</button></div>
</dialog>

<dialog class="dlg" id="exportDlg">
  <h2>Ekspor inbox</h2>
  <p class="sub mono" id="expAddr">—</p>
  <p class="hint">JSON memuat isi pesan; CSV metadata; ZIP berisi CSV + file .eml (yang tersedia).</p>
  <div class="row-actions">
    <button type="button" class="btn" id="expJson">JSON</button>
    <button type="button" class="btn" id="expCsv">CSV</button>
    <button type="button" class="btn" id="expZip">ZIP</button>
  </div>
  <div class="row-actions"><button type="button" class="btn btn-quiet" id="expClose">Tutup</button></div>
</dialog>

<dialog class="dlg" id="whDlg">
  <h2>Webhook</h2>
  <p class="sub mono" id="whAddr">—</p>
  <p class="hint">Kirim POST JSON setiap email baru. VIP ke atas. Maks 3 URL per alamat.</p>
  <div class="row-input" style="margin-top:10px">
    <input id="whUrl" placeholder="https://contoh.id/hook" aria-label="URL webhook">
    <button class="btn btn-primary" id="whAdd">Tambah</button>
  </div>
  <div class="auth-msg" id="whMsg" hidden></div>
  <div id="whList" style="margin-top:12px"></div>
  <div class="row-actions"><button type="button" class="btn" id="whClose">Tutup</button></div>
</dialog>

<dialog class="dlg" id="noteDlg">
  <h2>Label / catatan alamat</h2>
  <p class="sub mono" id="noteAddr">—</p>
  <div class="field">
    <label for="noteInput">Catatan singkat (maks 120 karakter)</label>
    <input id="noteInput" placeholder="mis. Netflix Trial, Akun GitHub 2" maxlength="120" autocomplete="off">
    <span class="hint">Kosongkan lalu simpan untuk menghapus label.</span>
  </div>
  <div class="row-actions">
    <button type="button" class="btn" id="noteCancel">Batal</button>
    <button type="button" class="btn btn-primary" id="noteSave">Simpan</button>
  </div>
</dialog>

<dialog class="dlg" id="matrixEditDlg" style="width:min(540px,94vw)">
  <h2 id="mxeTitle">Detail &amp; Vault Akun</h2>
  <p class="sub mono" id="mxeAddr">—</p>
  <div class="mx-grid-form" style="margin-top:8px">
    <div class="field" style="margin:0">
      <label for="mxeService">Layanan / Platform</label>
      <input id="mxeService" maxlength="60" autocomplete="off">
    </div>
    <div class="field" style="margin:0">
      <label for="mxeTag">Tag / Label</label>
      <input id="mxeTag" placeholder="#Alt-01" maxlength="40" autocomplete="off">
    </div>
  </div>
  <div class="mx-grid-form" style="margin-top:8px">
    <div class="field" style="margin:0">
      <label for="mxeUser">Username</label>
      <input id="mxeUser" maxlength="80" autocomplete="off">
    </div>
    <div class="field" style="margin:0">
      <label for="mxePass">Password</label>
      <div style="display:flex;gap:6px">
        <input id="mxePass" maxlength="200" autocomplete="off" class="mono">
        <button type="button" class="btn" id="mxeGenPass" style="height:36px;padding:0 10px;white-space:nowrap" title="Generate password kuat 18-karakter">🎲 Acak</button>
      </div>
    </div>
  </div>
  <div class="field" style="margin-top:10px">
    <label for="mxeTotp">2FA TOTP Secret (Base32 atau URI otpauth://)</label>
    <input id="mxeTotp" placeholder="JBSWY3DPEHPK3PXP" maxlength="200" autocomplete="off" class="mono">
  </div>
  <div class="field" style="margin-top:10px">
    <label for="mxeApiKey">API Key / Token / License Key (Vault)</label>
    <input id="mxeApiKey" placeholder="sk-... / token / license" maxlength="500" autocomplete="off" class="mono">
  </div>
  <div class="field" style="margin-top:10px">
    <label for="mxeRecovery">2FA Recovery / Backup Codes</label>
    <input id="mxeRecovery" placeholder="kode backup dipisah spasi/koma" maxlength="1000" autocomplete="off" class="mono">
  </div>
  <div class="mx-grid-form" style="margin-top:8px">
    <div class="field" style="margin:0">
      <label for="mxeOpsec">Catatan OPSEC (Browser Profile / Proxy)</label>
      <input id="mxeOpsec" placeholder="Brave Profile #3 · Proxy SG" maxlength="300" autocomplete="off">
    </div>
    <div class="field" style="margin:0">
      <label for="mxeStatus">Status Akun</label>
      <select id="mxeStatus">
        <option value="active">🟢 Active</option>
        <option value="trial">🟡 Trial</option>
        <option value="cooldown">🔵 Cooldown</option>
        <option value="burned">🔴 Burned / Suspended</option>
      </select>
    </div>
    <div class="field" style="margin:0">
      <label for="mxeTrial">Masa Trial / Expiry</label>
      <select id="mxeTrial">
        <option value="keep">Tetap (Tidak diubah)</option>
        <option value="0">Permanen (Hapus Timer)</option>
        <option value="3">Set Trial +3 Hari</option>
        <option value="7">Set Trial +7 Hari</option>
        <option value="14">Set Trial +14 Hari</option>
        <option value="30">Set Trial +30 Hari</option>
        <option value="90">Set Trial +90 Hari</option>
      </select>
    </div>
  </div>
  <div class="auth-msg" id="mxeMsg" hidden></div>
  <div class="row-actions" style="margin-top:14px">
    <button type="button" class="btn" id="mxeCancel">Batal</button>
    <button type="button" class="btn btn-primary" id="mxeSave">Simpan Perubahan</button>
  </div>
</dialog>

<div class="navsheet" id="navSheet" data-open="false">
  <button class="close" id="navClose">Tutup</button>
  <div style="margin-top:16px" id="navSheetBody"></div>
</div>
`;
