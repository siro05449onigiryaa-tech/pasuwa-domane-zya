// シンプルなパスワードマネージャー（学習用）
(function(){
  const LS_MASTER = 'pm_master_v1';
  const LS_MASTER_HISTORY = 'pm_master_history_v1';
  const LS_ENTRIES = 'pm_entries_v1_enc';

  // ヘルパー: SHA-256 ハッシュ（Hex）
  async function hashPassword(pw){
    const enc = new TextEncoder().encode(pw);
    const buf = await crypto.subtle.digest('SHA-256', enc);
    return Array.from(new Uint8Array(buf)).map(b=>b.toString(16).padStart(2,'0')).join('');
  }

  // 暗号化ユーティリティ: PBKDF2 -> AES-GCM
  function genSalt(){ const s=new Uint8Array(16); crypto.getRandomValues(s); return btoa(String.fromCharCode(...s)); }
  function fromB64(b64){ const bin=atob(b64); const arr=new Uint8Array(bin.length); for(let i=0;i<bin.length;i++) arr[i]=bin.charCodeAt(i); return arr; }
  function toB64(arr){ return btoa(String.fromCharCode(...new Uint8Array(arr))); }

  async function deriveKey(pw, saltB64, iterations=100000){
    const salt = fromB64(saltB64);
    const enc = new TextEncoder().encode(pw);
    const baseKey = await crypto.subtle.importKey('raw', enc, {name:'PBKDF2'}, false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey({name:'PBKDF2', salt, iterations, hash:'SHA-256'}, baseKey, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
    return key;
  }

  async function encryptWithKey(key, obj){
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const data = new TextEncoder().encode(JSON.stringify(obj));
    const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, key, data);
    const combined = new Uint8Array(iv.byteLength + ct.byteLength);
    combined.set(iv,0); combined.set(new Uint8Array(ct), iv.byteLength);
    return toB64(combined);
  }

  async function decryptWithKey(key, b64){
    const combined = fromB64(b64);
    const iv = combined.slice(0,12);
    const ct = combined.slice(12);
    const plain = await crypto.subtle.decrypt({name:'AES-GCM', iv}, key, ct);
    return JSON.parse(new TextDecoder().decode(plain));
  }

  // DOM
  const setMasterArea = document.getElementById('setMasterArea');
  const loginArea = document.getElementById('loginArea');
  const authSection = document.getElementById('authSection');
  const mainSection = document.getElementById('mainSection');
  const setMasterBtn = document.getElementById('setMasterBtn');
  const loginBtn = document.getElementById('loginBtn');
  const logoutBtn = document.getElementById('logoutBtn');
  const loginError = document.getElementById('loginError');

  const entryForm = document.getElementById('entryForm');
  const listEl = document.getElementById('list');
  const searchInput = document.getElementById('searchInput');
  const clearSearch = document.getElementById('clearSearch');

  // 初期化
  // グローバルエラー表示（簡易デバッグ用）
  window.addEventListener('error', (ev)=>{
    try{ console.error('Global error', ev.error || ev.message); }catch(e){}
  });
  let currentKey = null;
  async function init(){
    const masterRaw = localStorage.getItem(LS_MASTER);
    if(!masterRaw){
      setMasterArea.hidden = false;
      loginArea.hidden = true;
    } else {
      setMasterArea.hidden = true;
      loginArea.hidden = false;
    }
    bindEvents();
    // strength meter for initial set
    const setPw = document.getElementById('setMasterPassword');
    if(setPw){ setPw.addEventListener('input', ()=>updateMeter('setPwMeter','setPwText', setPw.value)); }
    // modal meter hook
    const modalNew = document.getElementById('modalNewPw');
    if(modalNew) modalNew.addEventListener('input', ()=>updateMeter('modalPwMeter','modalPwText', modalNew.value));
  }

  function bindEvents(){
    if(setMasterBtn) setMasterBtn.addEventListener('click', onSetMaster);
    if(loginBtn) loginBtn.addEventListener('click', onLogin);
    if(logoutBtn) logoutBtn.addEventListener('click', onLogout);
    if(entryForm) entryForm.addEventListener('submit', onSaveEntry);
    if(clearSearch) clearSearch.addEventListener('click', ()=>{searchInput.value=''; renderList();});
    if(searchInput) searchInput.addEventListener('input', debounce(renderList,150));
    const r1 = document.getElementById('resetMasterBtn'); if(r1) r1.addEventListener('click', onResetMaster);
    const r2 = document.getElementById('resetMasterBtn2'); if(r2) r2.addEventListener('click', onResetMaster);
    const gen = document.getElementById('genPw'); if(gen) gen.addEventListener('click', ()=>{ const p = document.getElementById('password'); if(p) p.value = generatePassword(12); });
    const exp = document.getElementById('exportBtn'); if(exp) exp.addEventListener('click', onExport);
    const imp = document.getElementById('importBtn'); if(imp) imp.addEventListener('click', ()=>{ const f = document.getElementById('importFile'); if(f) f.click(); });
    const impFile = document.getElementById('importFile'); if(impFile) impFile.addEventListener('change', onImportFile);
    // modal controls (may not exist on old pages)
    const modal = document.getElementById('resetModal');
    if(modal){
      const cancel = document.getElementById('modalCancel');
      const submit = document.getElementById('modalSubmit');
      if(cancel) cancel.addEventListener('click', ()=>{ modal.hidden = true; clearModalFields(); });
      if(submit) submit.addEventListener('click', onModalSubmit);
    }
  }

  function showMain(){
    authSection.hidden = true;
    mainSection.hidden = false;
    logoutBtn.hidden = false;
    renderList();
  }

  function showAuth(){
    authSection.hidden = false;
    mainSection.hidden = true;
    logoutBtn.hidden = true;
    // reset form
    entryForm.reset();
    document.getElementById('entryId').value='';
    document.getElementById('formTitle').textContent='新しい登録';
    document.getElementById('cancelEdit').hidden = true;
    // ログアウト時にマスターパスワード入力とログインエラーをリセット
    const loginPw = document.getElementById('loginPassword');
    if(loginPw) loginPw.value = '';
    const setPw = document.getElementById('setMasterPassword');
    if(setPw) setPw.value = '';
    const setPwConfirm = document.getElementById('setMasterPasswordConfirm');
    if(setPwConfirm) setPwConfirm.value = '';
    if(loginError) loginError.hidden = true;
  }

  async function onSetMaster(){
    const pw = document.getElementById('setMasterPassword').value;
    const pwc = document.getElementById('setMasterPasswordConfirm').value;
    if(!pw){alert('パスワードを入力してください');return}
    if(pw!==pwc){alert('確認が一致しません');return}
    if(pw.length < 8){ alert('パスワードは8文字以上にしてください'); return }
    const h = await hashPassword(pw);
    const salt = genSalt();
    const masterObj = {hash: h, salt, iterations:100000};
    localStorage.setItem(LS_MASTER, JSON.stringify(masterObj));
    // init history
    localStorage.setItem(LS_MASTER_HISTORY, JSON.stringify([]));
    // derive key and encrypt existing plaintext entries if any
    currentKey = await deriveKey(pw, salt, masterObj.iterations);
    const plainRaw = localStorage.getItem('pm_entries_v1');
    if(plainRaw){
      try{
        const items = JSON.parse(plainRaw);
        const enc = await encryptWithKey(currentKey, items);
        localStorage.setItem(LS_ENTRIES, enc);
        localStorage.removeItem('pm_entries_v1');
      }catch(e){/* ignore */}
    }
    alert('マスターパスワードを設定しました');
    setMasterArea.hidden = true;
    loginArea.hidden = false;
  }

  async function onLogin(){
    const pw = document.getElementById('loginPassword').value||'';
    const h = await hashPassword(pw);
    const storedRaw = localStorage.getItem(LS_MASTER);
    if(!storedRaw){ alert('マスターが設定されていません'); return }
    const stored = JSON.parse(storedRaw);
    if(h===stored.hash){
      // derive key
      currentKey = await deriveKey(pw, stored.salt, stored.iterations);
      loginError.hidden = true;
      showMain();
    } else {
      loginError.hidden = false;
    }
  }

  function onLogout(){
    // wipe in-memory key
    currentKey = null;
    showAuth();
  }

  // Entries
  async function loadEntries(){
    const raw = localStorage.getItem(LS_ENTRIES);
    if(!raw) return [];
    // if raw looks like JSON array (migration), parse as plaintext
    if(raw.trim().startsWith('[')){
      try{return JSON.parse(raw);}catch(e){return []}
    }
    if(!currentKey) return [];
    try{
      const arr = await decryptWithKey(currentKey, raw);
      return Array.isArray(arr)?arr:[];
    }catch(e){console.error('decrypt failed',e); return []}
  }

  async function saveEntries(items){
    if(currentKey){
      const enc = await encryptWithKey(currentKey, items);
      localStorage.setItem(LS_ENTRIES, enc);
    } else {
      // fallback plaintext (shouldn't happen after encryption enabled)
      localStorage.setItem(LS_ENTRIES, JSON.stringify(items));
    }
  }

  async function onSaveEntry(e){
    e.preventDefault();
    const id = document.getElementById('entryId').value;
    const data = {
      serviceName: document.getElementById('serviceName').value.trim(),
      loginId: document.getElementById('loginId').value.trim(),
      password: document.getElementById('password').value,
      memo: document.getElementById('memo').value.trim()
    };
    if(!data.serviceName){alert('サービス名は必須です');return}
    const items = await loadEntries();
    if(id){
      const idx = items.findIndex(it=>String(it.id)===String(id));
      if(idx>=0){items[idx] = {...items[idx], ...data};}
    } else {
      const newId = Date.now();
      items.unshift({id:newId, ...data});
    }
    await saveEntries(items);
    entryForm.reset();
    document.getElementById('entryId').value='';
    document.getElementById('formTitle').textContent='新しい登録';
    document.getElementById('cancelEdit').hidden = true;
    renderList();
  }

  async function renderList(){
    const q = (searchInput.value||'').trim().toLowerCase();
    const items = (await loadEntries()).filter(it=>!q||it.serviceName.toLowerCase().includes(q));
    listEl.innerHTML = '';
    if(items.length===0){ listEl.innerHTML = '<div class="muted">登録なし</div>'; return }
    items.forEach(it=>{
      const el = document.createElement('div'); el.className='entry';
      const s = document.createElement('div'); s.innerHTML = `<div class="service">${escapeHtml(it.serviceName)}</div><div class="meta">${escapeHtml(it.loginId)}</div>`; s.className='serviceCol';
      const pw = document.createElement('div'); pw.className='meta pw'; pw.textContent = maskPassword(it.password);
      const memo = document.createElement('div'); memo.className='meta'; memo.textContent = it.memo||'';
      const actions = document.createElement('div'); actions.className='actions';

      const toggleBtn = document.createElement('button'); toggleBtn.textContent='表示'; toggleBtn.className='small btn-ghost';
      toggleBtn.addEventListener('click', ()=>{
        if(pw.textContent===maskPassword(it.password)) pw.textContent = it.password; else pw.textContent = maskPassword(it.password);
      });

      const editBtn = document.createElement('button'); editBtn.textContent='編集'; editBtn.className='small btn-ghost';
      editBtn.addEventListener('click', ()=>{ startEdit(it.id); });

      const delBtn = document.createElement('button'); delBtn.textContent='削除'; delBtn.className='small btn-ghost';
      delBtn.addEventListener('click', ()=>{ if(confirm('削除しますか？')){ deleteEntry(it.id); } });

      actions.appendChild(toggleBtn); actions.appendChild(editBtn); actions.appendChild(delBtn);

      // Assemble
      el.appendChild(s);
      el.appendChild(pw);
      el.appendChild(memo);
      el.appendChild(actions);
      listEl.appendChild(el);
    });
  }

  async function startEdit(id){
    const items = await loadEntries();
    const it = items.find(x=>x.id===id || String(x.id)===String(id));
    if(!it) return;
    document.getElementById('entryId').value = it.id;
    document.getElementById('serviceName').value = it.serviceName;
    document.getElementById('loginId').value = it.loginId;
    document.getElementById('password').value = it.password;
    document.getElementById('memo').value = it.memo;
    document.getElementById('formTitle').textContent = '編集';
    document.getElementById('cancelEdit').hidden = false;
    document.getElementById('cancelEdit').addEventListener('click', ()=>{ entryForm.reset(); document.getElementById('entryId').value=''; document.getElementById('formTitle').textContent='新しい登録'; document.getElementById('cancelEdit').hidden=true; });
    window.scrollTo({top:0,behavior:'smooth'});
  }

  function deleteEntry(id){
    (async()=>{
      const items = (await loadEntries()).filter(x=>String(x.id)!==String(id));
      await saveEntries(items);
      renderList();
    })();
  }

  // マスター再設定 / 初期化
  async function onResetMaster(){
    // ask whether change or full reset
    if(!localStorage.getItem(LS_MASTER)){
      if(confirm('マスターが未設定です。完全初期化を行いますか？')){
        localStorage.removeItem(LS_ENTRIES);
        localStorage.removeItem(LS_MASTER);
        localStorage.removeItem(LS_MASTER_HISTORY);
        currentKey = null;
        alert('初期化しました');
        showAuth();
      }
      return;
    }
    const doChange = confirm('マスターを変更する場合は「OK」、完全に初期化する場合は「キャンセル」を押してください。');
    if(!doChange){
      if(!confirm('全てのデータとマスターを削除します。本当によいですか？')) return;
      localStorage.removeItem(LS_ENTRIES);
      localStorage.removeItem(LS_MASTER);
      localStorage.removeItem(LS_MASTER_HISTORY);
      currentKey = null;
      alert('初期化しました');
      showAuth();
      return;
    }
    // open modal
    const modal = document.getElementById('resetModal');
    if(modal){ clearModalFields(); modal.hidden = false; }
  }

  function clearModalFields(){
    const fields = ['modalCurrentPw','modalNewPw','modalNewPwConfirm'];
    fields.forEach(id=>{ const el=document.getElementById(id); if(el) el.value=''; });
    updateMeter('modalPwMeter','modalPwText','');
  }

  async function onModalSubmit(){
    const cur = document.getElementById('modalCurrentPw').value;
    const nw = document.getElementById('modalNewPw').value;
    const nw2 = document.getElementById('modalNewPwConfirm').value;
    const modal = document.getElementById('resetModal');
    if(!cur || !nw || !nw2){ alert('全ての項目を入力してください'); return }
    if(nw !== nw2){ alert('確認が一致しません'); return }
    if(nw.length < 8){ alert('新しいパスワードは8文字以上にしてください'); return }
    if(nw === cur){ alert('現在のパスワードと同じものは新しいパスワードにできません'); return }
    const masterRaw = JSON.parse(localStorage.getItem(LS_MASTER));
    if(!masterRaw){ alert('マスターが未設定です'); return }
    const curHash = await hashPassword(cur);
    if(curHash !== masterRaw.hash){ alert('現在のパスワードが違います'); return }
    const nwHash = await hashPassword(nw);
    const history = JSON.parse(localStorage.getItem(LS_MASTER_HISTORY) || '[]');
    if(history.includes(nwHash) || nwHash === masterRaw.hash){ alert('以前使用したパスワードは再利用できません'); return }
    // decrypt existing entries using current
    let decrypted = [];
    try{
      const kcur = await deriveKey(cur, masterRaw.salt, masterRaw.iterations);
      decrypted = await decryptWithKey(kcur, localStorage.getItem(LS_ENTRIES));
    }catch(e){
      try{ decrypted = await loadEntries(); }catch(err){ decrypted = []; }
    }
    // create new master and re-encrypt
    const newSalt = genSalt();
    const newKey = await deriveKey(nw, newSalt, 100000);
    const enc = await encryptWithKey(newKey, decrypted || []);
    localStorage.setItem(LS_ENTRIES, enc);
    // update history
    const newHistory = history.slice(); newHistory.unshift(masterRaw.hash); while(newHistory.length>10) newHistory.pop();
    localStorage.setItem(LS_MASTER_HISTORY, JSON.stringify(newHistory));
    localStorage.setItem(LS_MASTER, JSON.stringify({hash:nwHash, salt:newSalt, iterations:100000}));
    currentKey = newKey;
    modal.hidden = true; clearModalFields();
    alert('マスターパスワードを変更しました');
    showMain();
  }

  // パスワード生成
  function generatePassword(len=12){
    const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+';
    let s=''; const a=new Uint32Array(len); crypto.getRandomValues(a);
    for(let i=0;i<len;i++) s += chars[a[i]%chars.length];
    return s;
  }

  // エクスポート/インポート
  async function onExport(){
    const masterRaw = localStorage.getItem(LS_MASTER); if(!masterRaw){ alert('マスター未設定'); return }
    const master = JSON.parse(masterRaw);
    const data = localStorage.getItem(LS_ENTRIES) || '';
    const out = {version:1, salt: master.salt, data};
    const blob = new Blob([JSON.stringify(out, null, 2)], {type:'application/json'});
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = 'pm_export.json'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
  }

  async function onImportFile(e){
    const f = e.target.files && e.target.files[0]; if(!f) return;
    const text = await f.text();
    try{
      const j = JSON.parse(text);
      if(!j.version || !j.data || !j.salt) throw new Error('invalid');
      if(!localStorage.getItem(LS_MASTER)){ alert('先にマスターパスワードを設定してください'); return }
      // import encrypted data and update salt used for data decryption
      const masterRaw = JSON.parse(localStorage.getItem(LS_MASTER));
      masterRaw.salt = j.salt; // allow using imported salt for key derivation
      localStorage.setItem(LS_MASTER, JSON.stringify(masterRaw));
      localStorage.setItem(LS_ENTRIES, j.data);
      alert('インポートしました。ログアウトして再ログインしてください。');
    }catch(err){ alert('インポート失敗: ファイル形式を確認してください'); }
    e.target.value='';
  }

  // utils
  function maskPassword(pw){ return pw? '•'.repeat(Math.max(6, pw.length)) : '' }
  function escapeHtml(s){ if(!s) return ''; return String(s).replace(/[&<>"']/g, c=>({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":"&#39;"}[c])); }
  function debounce(fn,ms){ let t; return (...a)=>{ clearTimeout(t); t=setTimeout(()=>fn(...a), ms); }; }

  function updateMeter(barId, textId, pw){
    const bar = document.getElementById(barId); const txt = document.getElementById(textId);
    if(!bar) return;
    const score = scorePassword(pw);
    bar.setAttribute('data-score', String(score));
    if(txt){
      const labels = ['無し','弱い','普通','強い','非常に強い'];
      txt.textContent = pw? labels[score] : '';
    }
  }

  function scorePassword(pw){
    if(!pw) return 0;
    let score = 0;
    if(pw.length >= 8) score++;
    if(pw.length >= 12) score++;
    if(/[a-z]/.test(pw) && /[A-Z]/.test(pw)) score++;
    if(/[0-9]/.test(pw) && /[^A-Za-z0-9]/.test(pw)) score++;
    if(score>4) score=4;
    return score;
  }

  // 起動
  init();

})();
