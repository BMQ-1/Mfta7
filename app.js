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
// إدارة حالة التطبيق ومساعدات DOM
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

// DOM References
let lockScreen, appContainer, errorEl;

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

// 🛡️ DOM Builder: حل نهائي لاستبدال innerHTML وبناء الشجرة برمجياً بأمان
function el(tag, props = {}, ...children) {
  const element = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === 'className') element.className = value;
    else if (key === 'dataset') {
      for(const [dKey, dVal] of Object.entries(value)) element.dataset[dKey] = dVal;
    }
    else if (key === 'style') element.style.cssText = value;
    else element[key] = value;
  }
  children.forEach(child => {
    if (!child) return;
    if (typeof child === 'string' || typeof child === 'number') {
      element.appendChild(document.createTextNode(child));
    } else if (child instanceof Node) {
      element.appendChild(child);
    }
  });
  return element;
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
  const clone = document.getElementById('app-template').content.cloneNode(true);
appContainer.appendChild(clone);
 // آمن لنسخ التمبلت الأساسي فقط
  
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
  
  appContainer.textContent = ''; // Wipe DOM immediately
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
// التصيير (Rendering) الخالي 100% من innerHTML
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
  bar.appendChild(el('div', { className: 'stat-pill' }, `🔑 ${entries.length} حساب محفوظ`));

  if(reused > 0 || weak > 0) {
    bar.appendChild(el('div', { className: 'stat-pill health-bad' }, `⚠️ ${weak} ضعيفة | ${reused} مكررة`));
  }
}

function renderTabs() {
  const cats = [...new Set(entries.map(e => e.category || 'عام'))];
  const w = document.getElementById('tabs-wrap');
  w.textContent = ''; 

  const createTab = (text, val, isActive) => {
    w.appendChild(el('div', { 
      className: `tab ${isActive ? 'active' : ''}`, 
      dataset: { action: 'set-cat', val: val } 
    }, text));
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
  grid.textContent = ''; // مسح آمن

  res.forEach((e, index) => {
    const isRev = revealedSet.has(e.id);
    const safeUrl = (e.url && (e.url.startsWith('http://') || e.url.startsWith('https://'))) ? e.url : '';
    const delay = Math.min(index * 0.05, 0.5); 

    // Header Construction
    const titleWrap = el('div', { style: 'flex:1;min-width:0' },
      el('div', { className: 'card-site-name' }, e.name || 'حساب بدون اسم'),
      safeUrl ? el('div', { className: 'card-site-url' }, safeUrl) : null
    );

    const headerContent = [
      el('img', { className: 'site-avatar', src: getAvatar(e.name || e.url), alt: '' }),
      titleWrap
    ];
    if(e.category) headerContent.push(el('div', { className: 'card-category' }, e.category));
    const header = el('div', { className: 'card-header' }, ...headerContent);

    // Body Construction - Helper function for rows
    const createRow = (label, value, actionField, isPw = false, isTotp = false) => {
      let valEl, extraBtn;
      
      if(isTotp) {
        valEl = el('div', { className: 'totp-display', id: `totp-${e.id}` }, '---');
      } else {
        const valStyle = isPw ? `letter-spacing:${isRev?'0':'4px'}; font-size:${isRev?'15px':'18px'}` : '';
        const valText = (isPw && !isRev) ? '••••••••' : (value || '—');
        valEl = el('div', { className: 'field-value', style: valStyle }, valText);
        if(isPw) extraBtn = el('button', { className: 'copy-btn', ariaLabel: 'إظهار', dataset: { action: 'toggle-rev', id: e.id } }, isRev ? '🙈' : '👁');
      }

      return el('div', { className: 'field-row' },
        el('div', { className: 'field-label' }, label),
        valEl,
        extraBtn,
        el('button', { className: 'copy-btn', ariaLabel: 'نسخ', dataset: { action: isTotp ? 'copy-totp' : 'copy', id: e.id, field: actionField } }, '📋')
      );
    };

    const bodyChildren = [
      createRow('اليوزر', e.username, 'username'),
      createRow('المرور', e.password, 'password', true)
    ];
    if(e.totp) bodyChildren.push(createRow('2FA', null, null, false, true));
    if(e.history && e.history.length) {
      bodyChildren.push(el('div', { className: 'history-list' }, `سجل التغييرات: ${e.history.map(h => isRev ? h : '***').join(' ، ')}`));
    }
    const body = el('div', { className: 'card-body' }, ...bodyChildren);

    // Footer Construction
    const footerChildren = [];
    if(safeUrl) { // Security: rel="noopener noreferrer" added
      footerChildren.push(el('a', { href: safeUrl, target: '_blank', rel: 'noopener noreferrer', style: 'text-decoration:none' }, 
        el('button', { className: 'btn-sm' }, '🌐 فتح الرابط')
      ));
    }
    footerChildren.push(
      el('button', { className: 'btn-sm', dataset: { action: 'edit', id: e.id } }, '✏️ تعديل'),
      el('button', { className: 'btn-sm danger', dataset: { action: 'req-delete', id: e.id } }, '🗑 حذف')
    );
    const footer = el('div', { className: 'card-footer' }, ...footerChildren);

    // Final Card Assembly
    const card = el('div', { className: 'card', style: `animation-delay: ${delay}s` }, header, body, footer);
    grid.appendChild(card);
  });
  
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
      case 'open-settings': 
        document.getElementById('current-pw-input').value = '';
        document.getElementById('change-pw-input').value = '';
        openM('settings-modal'); 
        break;
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

// Security: تأمين تغيير كلمة المرور عبر التحقق من الكلمة الحالية
async function changeMasterPassword() {
  const oldPw = document.getElementById('current-pw-input').value;
  const newPw = document.getElementById('change-pw-input').value;
  
  if(!oldPw) return showTst('⚠️ أدخل كلمة المرور الحالية');
  if(newPw.length < 8) return showTst('❌ كلمة المرور الجديدة قصيرة جداً');

  try {
    // اختبار كلمة المرور القديمة بتجربة فك التشفير
    const oldSalt = Uint8Array.from(atob(localStorage.getItem(SALT_KEY)), c => c.charCodeAt(0));
    const testKey = await deriveKey(oldPw, oldSalt);
    await decryptData(localStorage.getItem(STORAGE_KEY), testKey);
    
    // إذا نجح الاختبار، نولد مفتاحاً جديداً بالكامل
    const newSalt = generateSalt();
    localStorage.setItem(SALT_KEY, btoa(String.fromCharCode(...newSalt)));
    masterKey = await deriveKey(newPw, newSalt);
    await saveVault();
    
    closeM('settings-modal'); 
    showTst('✅ تم تغيير كلمة المرور وإعادة التشفير');
    document.getElementById('current-pw-input').value = '';
    document.getElementById('change-pw-input').value = '';
  } catch(e) {
    showTst('❌ كلمة المرور الحالية غير صحيحة');
  }
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
  lockScreen = document.getElementById('lock-screen');
  appContainer = document.getElementById('app-container');
  errorEl = document.getElementById('lock-error');

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

  initLock();
});
