// ==========================================
// التشفير والأمان الأساسي
// ==========================================
const STORAGE_KEY = 'miftah_enc_v3';
const SALT_KEY = 'miftah_salt_v3';

function generateSalt() { return crypto.getRandomValues(new Uint8Array(32)); }

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const raw = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 300000, hash: 'SHA-256' },
    raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function encryptData(data, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(data)));
  const combined = new Uint8Array(iv.length + ct.byteLength);
  combined.set(iv, 0); combined.set(new Uint8Array(ct), iv.length);
  return btoa(String.fromCharCode(...combined));
}

async function decryptData(b64, key) {
  const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const iv = buf.slice(0, 12);
  const ct = buf.slice(12);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ct);
  return JSON.parse(new TextDecoder().decode(pt));
}

function base32ToBytes(base32) {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "", bytes =[];
  for(let i=0; i<base32.length; i++) {
    const val = chars.indexOf(base32.charAt(i).toUpperCase());
    if(val === -1) continue;
    bits += val.toString(2).padStart(5, '0');
  }
  for(let i=0; i<bits.length - 7; i+=8) bytes.push(parseInt(bits.substr(i, 8), 2));
  return new Uint8Array(bytes);
}

async function generateTOTPCode(secretBase32) {
  try {
    if(!secretBase32) return null;
    const keyBytes = base32ToBytes(secretBase32);
    const key = await crypto.subtle.importKey('raw', keyBytes, {name: 'HMAC', hash: 'SHA-1'}, false, ['sign']);
    const epoch = Math.floor(Date.now() / 1000);
    const time = Math.floor(epoch / 30);
    const buffer = new ArrayBuffer(8);
    new DataView(buffer).setUint32(4, time, false);
    const sig = new Uint8Array(await crypto.subtle.sign('HMAC', key, buffer));
    const offset = sig[sig.length - 1] & 0xf;
    const code = ((sig[offset] & 0x7f) << 24 | (sig[offset + 1] & 0xff) << 16 | (sig[offset + 2] & 0xff) << 8 | sig[offset + 3] & 0xff) % 1000000;
    return { code: code.toString().padStart(6, '0'), timeRemaining: 30 - (epoch % 30) };
  } catch(e) { return null; }
}

// ==========================================
// إدارة حالة التطبيق و DOM Elements
// ==========================================
let masterKey = null;
let entries = [];
let activeCat = 'all';
let editId = null;
let revealedSet = new Set();
let totpInterval;
let lockTimer;
let currentDeleteId = null;
let pendingImportData = null;
let activityController;

// DOM References (Initialized on DOMContentLoaded)
let lockScreen, appContainer, errorEl;

function esc(s) { return String(s||'').replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m])); }

function getAvatar(name) {
  const canvas = document.createElement('canvas'); canvas.width = 100; canvas.height = 100;
  const ctx = canvas.getContext('2d');
  const colors = ['#6366f1', '#8b5cf6', '#ec4899', '#f59e0b', '#10b981', '#ef4444', '#06b6d4'];
  const char = (name || '?').charAt(0).toUpperCase();
  ctx.fillStyle = colors[char.charCodeAt(0) % colors.length] || colors[0];
  ctx.fillRect(0,0,100,100);
  ctx.fillStyle = '#ffffff'; ctx.font = 'bold 50px system-ui'; ctx.textAlign = 'center'; ctx.textBaseline = 'middle';
  ctx.fillText(char, 50, 54);
  return canvas.toDataURL('image/png');
}

// حماية Brute Force
function checkRateLimit() {
  const until = parseInt(sessionStorage.getItem('lockUntil') || '0');
  if(Date.now() < until) return `مقفول مؤقتاً. الرجاء الانتظار ${Math.ceil((until - Date.now()) / 1000)} ثانية`;
  return null;
}
function registerFail() {
  let f = parseInt(sessionStorage.getItem('fails') || '0') + 1;
  sessionStorage.setItem('fails', f);
  if(f >= 10) sessionStorage.setItem('lockUntil', Date.now() + 300000); 
  else if(f >= 5) sessionStorage.setItem('lockUntil', Date.now() + 30000); 
}
function resetFails() {
  sessionStorage.removeItem('fails');
  sessionStorage.removeItem('lockUntil');
}

// ==========================================
// الدخول والقفل
// ==========================================
const hasVault = () => !!localStorage.getItem(STORAGE_KEY);

function initLock() {
  document.getElementById('lock-title').textContent = hasVault() ? 'افتح خزنتك' : 'إنشاء خزنة جديدة';
  document.getElementById('confirm-wrap').style.display = hasVault() ? 'none' : 'flex';
  document.getElementById('lock-btn').textContent = hasVault() ? 'فتح الخزنة' : 'إنشاء وتشفير';
  document.getElementById('master-input').focus();
}

function showErr(m) { 
  errorEl.textContent = m; 
  errorEl.style.display = 'block'; 
  setTimeout(() => errorEl.style.display='none', 4500); 
}

function unlockApp() {
  lockScreen.style.opacity = '0';
  lockScreen.style.visibility = 'hidden';
  appContainer.innerHTML = document.getElementById('app-template').innerHTML;
  
  setTimeout(() => appContainer.classList.add('ready'), 50);
  document.getElementById('master-input').value = '';
  document.getElementById('master-confirm').value = '';
  
  startActivityTimer(); 
  bindAppEvents(activityController.signal);
  renderAll();
  totpInterval = setInterval(updateAllTOTP, 1000);
}

function lockApp() {
  masterKey = null; entries = []; revealedSet.clear(); clearInterval(totpInterval);
  activityController?.abort(); 
  
  // Wipe DOM immediately to prevent visual data leak window
  appContainer.textContent = ''; 
  appContainer.classList.remove('ready');
  
  lockScreen.style.visibility = 'visible';
  lockScreen.style.opacity = '1';
  document.getElementById('screen-warning').style.display = 'none';
  initLock();
}

function startActivityTimer() {
  activityController = new AbortController();
  const sig = { signal: activityController.signal };
  const reset = () => { clearTimeout(lockTimer); if(masterKey) lockTimer = setTimeout(lockApp, 5 * 60000); };
  ['mousemove','keydown','touchstart'].forEach(e => document.addEventListener(e, reset, sig));
  document.addEventListener('visibilitychange', () => { if(document.hidden && masterKey) lockTimer = setTimeout(lockApp, 15000); else reset(); }, sig);
  reset();
}

async function saveVault() {
  const enc = await encryptData(entries, masterKey);
  localStorage.setItem(STORAGE_KEY, enc);
}

// ==========================================
// التصيير (Rendering) باستخدام DOM API
// ==========================================
function renderAll() { renderStats(); renderTabs(); renderCards(); }

function renderStats() {
  const pwSet = new Set(); let reused = 0, weak = 0;
  entries.forEach(e => {
    if(e.password) {
      if(pwSet.has(e.password)) reused++; else pwSet.add(e.password);
      if(e.password.length < 8) weak++;
    }
  });
  
  const bar = document.getElementById('stats-bar');
  bar.textContent = ''; 

  const countPill = document.createElement('div');
  countPill.className = 'stat-pill';
  countPill.textContent = `🔑 ${entries.length} حساب محفوظ`;
  bar.appendChild(countPill);

  if(reused > 0 || weak > 0) {
    const healthPill = document.createElement('div');
    healthPill.className = 'stat-pill health-bad';
    healthPill.textContent = `⚠️ ${weak} ضعيفة | ${reused} مكررة`;
    bar.appendChild(healthPill);
  }
}

function renderTabs() {
  const cats = [...new Set(entries.map(e => e.category || 'عام'))];
  const w = document.getElementById('tabs-wrap');
  w.textContent = ''; 

  const createTab = (text, val, isActive) => {
    const t = document.createElement('div');
    t.className = `tab ${isActive ? 'active' : ''}`;
    t.dataset.action = 'set-cat';
    t.dataset.val = val;
    t.textContent = text;
    w.appendChild(t);
  };

  createTab('الكل', 'all', activeCat === 'all');
  cats.forEach(c => createTab(c, c, activeCat === c));
}

function renderCards() {
  const q = document.getElementById('search-input').value.toLowerCase();
  const res = entries.filter(e => 
    (activeCat === 'all' || (e.category || 'عام') === activeCat) &&
    ((e.name||'').toLowerCase().includes(q) || (e.url||'').toLowerCase().includes(q) || (e.username||'').toLowerCase().includes(q))
  );

  const grid = document.getElementById('cards-grid');
  grid.innerHTML = res.map((e, index) => {
    const isRev = revealedSet.has(e.id);
    const safeUrl = (e.url && (e.url.startsWith('http://') || e.url.startsWith('https://'))) ? e.url : '';
    const delay = Math.min(index * 0.05, 0.5); 
    
    return `
    <div class="card" style="animation-delay: ${delay}s">
      <div class="card-header">
        <img class="site-avatar" src="${getAvatar(e.name || e.url)}" alt="">
        <div style="flex:1;min-width:0">
          <div class="card-site-name">${esc(e.name || 'حساب بدون اسم')}</div>
          ${safeUrl ? `<div class="card-site-url">${esc(safeUrl)}</div>` : ''}
        </div>
        ${e.category ? `<div class="card-category">${esc(e.category)}</div>` : ''}
      </div>
      <div class="card-body">
        <div class="field-row">
          <div class="field-label">اليوزر</div>
          <div class="field-value">${esc(e.username || '—')}</div>
          <button class="copy-btn" aria-label="نسخ المستخدم" data-action="copy" data-id="${e.id}" data-field="username" title="نسخ">📋</button>
        </div>
        <div class="field-row">
          <div class="field-label">المرور</div>
          <div class="field-value" style="letter-spacing:${isRev?'0':'4px'}; font-size:${isRev?'15px':'18px'}">${isRev ? esc(e.password) : '••••••••'}</div>
          <button class="copy-btn" aria-label="إظهار" data-action="toggle-rev" data-id="${e.id}">${isRev?'🙈':'👁'}</button>
          <button class="copy-btn" aria-label="نسخ كلمة المرور" data-action="copy" data-id="${e.id}" data-field="password" title="نسخ">📋</button>
        </div>
        ${e.totp ? `<div class="field-row"><div class="field-label">2FA</div><div class="totp-display" id="totp-${e.id}">---</div><button class="copy-btn" aria-label="نسخ الرمز" data-action="copy-totp" data-id="${e.id}">📋</button></div>` : ''}
        ${e.history && e.history.length ? `<div class="history-list">سجل التغييرات: ${e.history.map(h => isRev?esc(h):'***').join(' ، ')}</div>` : ''}
      </div>
      <div class="card-footer">
        ${safeUrl ? `<a href="${safeUrl}" target="_blank" rel="noopener" style="text-decoration:none"><button class="btn-sm">🌐 فتح الرابط</button></a>` : ''}
        <button class="btn-sm" data-action="edit" data-id="${e.id}">✏️ تعديل</button>
        <button class="btn-sm danger" data-action="req-delete" data-id="${e.id}">🗑 حذف</button>
      </div>
    </div>`;
  }).join('');
  
  document.getElementById('screen-warning').style.display = revealedSet.size > 0 ? 'block' : 'none';
}

async function updateAllTOTP() {
  for(const e of entries) {
    if(e.totp && document.getElementById(`totp-${e.id}`)) {
      const t = await generateTOTPCode(e.totp);
      if(t) {
        const el = document.getElementById(`totp-${e.id}`);
        el.textContent = `${t.code} (${t.timeRemaining}s)`;
        el.dataset.code = t.code; 
      }
    }
  }
}

// ==========================================
// النسخ والأدوات
// ==========================================
let cbTimeout;
async function copyDataText(text) {
  if(!text) return;
  try {
    await navigator.clipboard.writeText(text);
    showTst('✅ تم النسخ! سيتم مسح الحافظة بعد 30 ثانية');
    clearTimeout(cbTimeout);
    cbTimeout = setTimeout(() => {
      navigator.clipboard.writeText('').catch(()=>{}); 
      showTst('🧹 تم تنظيف الحافظة تلقائياً');
    }, 30000);
  } catch(e) { showTst('❌ متصفحك يحتاج إذن الحافظة — تفاعل مع الصفحة أولاً'); }
}

function showTst(m) { 
  const t = document.getElementById('toast'); 
  t.textContent = m;
  t.classList.add('show'); 
  setTimeout(()=>t.classList.remove('show'), 3500); 
}

// ==========================================
// معالجة الأحداث والمنطق الأساسي (Event Delegation)
// ==========================================
function bindAppEvents(signal) {
  const opts = { signal };

  document.getElementById('search-input').addEventListener('input', renderCards, opts);
  document.getElementById('f-pass').addEventListener('input', (e) => checkPasswordStrength(e.target.value), opts);

  appContainer.addEventListener('click', async (e) => {
    const target = e.target.closest('[data-action]');
    if(!target) return;
    
    const action = target.dataset.action;
    const id = target.dataset.id;
    const val = target.dataset.val;
    const field = target.dataset.field;

    switch(action) {
      case 'lock-app': lockApp(); break;
      case 'open-settings': openM('settings-modal'); break;
      case 'open-add': editId = null; clearForm(); openM('form-modal'); break;
      case 'close-modal': closeM(target.dataset.target); break;
      case 'set-cat': activeCat = val; renderAll(); break;
      case 'copy': 
        const entry = entries.find(x => x.id === id);
        if(entry && field && entry[field]) copyDataText(entry[field]);
        break;
      case 'toggle-rev': if(revealedSet.has(id)) revealedSet.delete(id); else revealedSet.add(id); renderCards(); break;
      case 'copy-totp': const tEl = document.getElementById(`totp-${id}`); if(tEl) copyDataText(tEl.dataset.code); break;
      case 'edit': editEntryForm(id); break;
      case 'req-delete': currentDeleteId = id; document.getElementById('delete-confirm-input').value=''; openM('confirm-modal'); break;
      case 'confirm-delete': executeDelete(); break;
      case 'generate-pw': generateStrongPassword(); break;
      case 'toggle-form-pw': toggleFormPassword(target); break;
      case 'save-entry': saveEntryForm(); break;
      case 'export-vault': exportVault(); break;
      case 'change-master-pw': changeMasterPassword(); break;
      case 'process-import': processImport(); break;
    }
  }, opts);

  document.getElementById('import-file').addEventListener('change', (e) => {
    const f = e.target.files[0]; if(!f) return;
    if(f.size > 5 * 1024 * 1024) { e.target.value=''; return showTst('❌ الملف كبير جداً'); }
    
    const reader = new FileReader();
    reader.onload = (ev) => {
      try {
        pendingImportData = JSON.parse(ev.target.result);
        document.getElementById('import-pw-input').value = '';
        closeM('settings-modal');
        openM('import-pw-modal');
      } catch(err) { showTst('❌ تأكد أن الملف تم تصديره من مفتاح ولم يتم تعديله'); }
      e.target.value = '';
    };
    reader.readAsText(f);
  }, opts);

  document.addEventListener('keydown', (e) => {
    const openModal = document.querySelector('.modal-overlay.open');
    if (!openModal) return;

    if (e.key === 'Escape') {
      openModal.classList.remove('open');
      return;
    }

    if (e.key === 'Tab') {
      const focusable = openModal.querySelectorAll('button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])');
      if (focusable.length === 0) return;
      
      const first = focusable[0];
      const last = focusable[focusable.length - 1];

      if (e.shiftKey) { 
        if (document.activeElement === first) { e.preventDefault(); last.focus(); }
      } else { 
        if (document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    }
  }, opts);
}

function openM(id) { 
  const m = document.getElementById(id);
  m.classList.add('open'); 
  const firstInput = m.querySelector('input');
  if(firstInput) setTimeout(() => firstInput.focus(), 100);
}
function closeM(id) { document.getElementById(id).classList.remove('open'); }
function clearForm() { 
  ['f-url','f-name','f-user','f-pass','f-totp','f-cat'].forEach(id => document.getElementById(id).value = ''); 
  checkPasswordStrength('');
}

function checkPasswordStrength(pw) {
  const bar = document.getElementById('f-pw-bar');
  if(!bar) return;
  if(!pw) { bar.style.width = '0'; return; }
  
  let score = 0;
  if(pw.length > 7) score++;
  if(pw.length > 12) score++;
  if(/[A-Z]/.test(pw) && /[a-z]/.test(pw)) score++;
  if(/[0-9]/.test(pw)) score++;
  if(/[^A-Za-z0-9]/.test(pw)) score++;

  const uniqueChars = new Set(pw).size;
  if(pw.length > 0 && uniqueChars < pw.length * 0.5) score = Math.max(0, score - 2);

  const colors = ['#ef4444', '#f59e0b', '#10b981', '#10b981'];
  const widths = ['25%', '50%', '80%', '100%'];
  let idx = Math.min(Math.max(score - 1, 0), 3);
  
  bar.style.width = widths[idx];
  bar.style.backgroundColor = colors[idx];
}

function editEntryForm(id) {
  editId = id; const e = entries.find(x => x.id === id); if(!e) return;
  ['url','name','user','pass','totp','cat'].forEach(k => document.getElementById('f-'+k).value = e[k==='user'?'username':k==='pass'?'password':k] || '');
  document.getElementById('f-pass').type = 'password';
  checkPasswordStrength(e.password);
  openM('form-modal');
}

async function executeDelete() {
  if(document.getElementById('delete-confirm-input').value !== 'DELETE') return showTst('❌ اكتب DELETE بشكل صحيح بالأحرف الكبيرة');
  entries = entries.filter(e => e.id !== currentDeleteId);
  await saveVault(); closeM('confirm-modal'); renderAll(); showTst('🗑 تم الحذف بنجاح');
}

function generateStrongPassword() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789!@#$%^&*';
  let pw = ''; const max = Math.floor(0xFFFFFFFF / chars.length) * chars.length;
  while(pw.length < 18) {
    const r = crypto.getRandomValues(new Uint32Array(1))[0];
    if(r < max) pw += chars[r % chars.length];
  }
  const inp = document.getElementById('f-pass');
  inp.value = pw;
  inp.type = 'text';
  checkPasswordStrength(pw);
}

function toggleFormPassword(btn) {
  const inp = document.getElementById('f-pass');
  inp.type = inp.type === 'password' ? 'text' : 'password';
  btn.textContent = inp.type === 'password' ? '👁' : '🙈';
}

async function saveEntryForm() {
  const totpVal = document.getElementById('f-totp').value.replace(/\s/g,'').toUpperCase();
  if(totpVal && !/^[A-Z2-7]+=*$/.test(totpVal)) return showTst('❌ رمز TOTP غير صحيح (يجب أن يكون Base32)');

  const data = {
    url: document.getElementById('f-url').value.trim(),
    name: document.getElementById('f-name').value.trim(),
    username: document.getElementById('f-user').value.trim(),
    password: document.getElementById('f-pass').value,
    category: document.getElementById('f-cat').value.trim(),
    totp: totpVal,
    updated: Date.now()
  };
  
  if(!data.password) return showTst('⚠️ كلمة المرور مطلوبة');

  if(editId) {
    const idx = entries.findIndex(x => x.id === editId);
    if(entries[idx].password !== data.password) {
      data.history = [entries[idx].password, ...(entries[idx].history ||[])].slice(0, 5);
    } else { data.history = entries[idx].history; }
    entries[idx] = { ...entries[idx], ...data };
  } else {
    entries.unshift({ id: crypto.randomUUID(), ...data });
  }
  await saveVault(); closeM('form-modal'); renderAll(); showTst('✅ تم الحفظ في الخزنة');
}

function exportVault() {
  const enc = localStorage.getItem(STORAGE_KEY), salt = localStorage.getItem(SALT_KEY);
  const blob = new Blob([JSON.stringify({ v:3, enc, salt })], { type: 'application/json' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); 
  const rand = crypto.getRandomValues(new Uint32Array(1))[0].toString(16);
  a.download = `Miftah_Vault_${rand}.json`; 
  a.click();
}

async function changeMasterPassword() {
  const np = document.getElementById('change-pw-input').value;
  if(np.length < 8) return showTst('❌ كلمة المرور قصيرة جداً');
  const newSalt = generateSalt();
  localStorage.setItem(SALT_KEY, btoa(String.fromCharCode(...newSalt)));
  masterKey = await deriveKey(np, newSalt);
  await saveVault();
  closeM('settings-modal'); showTst('✅ تم تغيير كلمة المرور وإعادة التشفير');
  document.getElementById('change-pw-input').value = '';
}

const isValidEntry = (e) => 
  e && typeof e.id === 'string' && e.id.length < 100 &&
  typeof e.password === 'string' && e.password.length < 10000 &&
  (!e.url || (typeof e.url === 'string' && e.url.length < 2000)) &&
  (!e.username || (typeof e.username === 'string' && e.username.length < 500)) &&
  (!e.name || (typeof e.name === 'string' && e.name.length < 500));

async function processImport() {
  if(!pendingImportData) return;
  const pass = document.getElementById('import-pw-input').value;
  if(!pass) return showTst('⚠️ أدخل كلمة المرور');
  
  try {
    const testSalt = Uint8Array.from(atob(pendingImportData.salt), c => c.charCodeAt(0));
    const testKey = await deriveKey(pass, testSalt);
    const importedData = await decryptData(pendingImportData.enc, testKey);
    
    const existingIds = new Set(entries.map(e => e.id));
    const newEntries = importedData.filter(e => isValidEntry(e) && !existingIds.has(e.id));
    
    entries = [...newEntries, ...entries];
    await saveVault();
    renderAll(); 
    closeM('import-pw-modal');
    showTst(`📥 تم دمج ${newEntries.length} حساب جديد بنجاح`);
    pendingImportData = null;
  } catch(err) { 
    showTst('❌ كلمة المرور خاطئة أو الملف تالف'); 
  }
}

// ==========================================
// التهيئة الابتدائية (Initial Boot)
// ==========================================
document.addEventListener('DOMContentLoaded', () => {
  // ربط عناصر الـ DOM الأساسية
  lockScreen = document.getElementById('lock-screen');
  appContainer = document.getElementById('app-container');
  errorEl = document.getElementById('lock-error');

  // استماع لأزرار شاشة القفل الرئيسية
  document.getElementById('lock-btn').addEventListener('click', async () => {
    const rLimit = checkRateLimit();
    if(rLimit) return showErr(rLimit);

    const pw = document.getElementById('master-input').value;
    if(!pw) return showErr('أدخل كلمة المرور');

    if(!hasVault()) {
      const conf = document.getElementById('master-confirm').value;
      if(pw !== conf) return showErr('كلمتا المرور غير متطابقتين');
      if(pw.length < 8) return showErr('يجب أن تتكون من 8 أحرف كحد أدنى');
      
      const salt = generateSalt();
      localStorage.setItem(SALT_KEY, btoa(String.fromCharCode(...salt)));
      masterKey = await deriveKey(pw, salt);
      entries = [];
      await saveVault();
      unlockApp();
    } else {
      try {
        const salt = Uint8Array.from(atob(localStorage.getItem(SALT_KEY)), c => c.charCodeAt(0));
        const testKey = await deriveKey(pw, salt);
        entries = await decryptData(localStorage.getItem(STORAGE_KEY), testKey);
        masterKey = testKey;
        resetFails();
        unlockApp();
      } catch(e) {
        registerFail();
        showErr('كلمة المرور خاطئة — لا يمكن استرجاعها إذا نُسيت');
      }
    }
  });

  document.getElementById('master-input').addEventListener('keydown', (e) => {
    if(e.key === 'Enter' && hasVault()) document.getElementById('lock-btn').click();
  });
  
  document.getElementById('master-confirm').addEventListener('keydown', (e) => {
    if(e.key === 'Enter') document.getElementById('lock-btn').click();
  });

  // تشغيل واجهة القفل
  initLock();
});
