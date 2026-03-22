/* ══════════════════════════════════════════════════════════
   LE FIL D'ARIANE — Application Logic (v2 — Sécurisée)
   Dépend de : security.js (chargé en premier)
══════════════════════════════════════════════════════════ */

'use strict';

const Store = {
  get: (key) => { try { return JSON.parse(localStorage.getItem('fda_' + key)); } catch { return null; } },
  set: (key, val) => { try { localStorage.setItem('fda_' + key, JSON.stringify(val)); return true; } catch { return false; } },
  del: (key) => localStorage.removeItem('fda_' + key)
};

const App = {
  currentView: 'view-splash',
  currentSection: 'dashboard',

  init() {
    if (!SecurityInit.run()) return;
    const session = Session.validate();
    const user = Store.get('user');
    if (session && user) {
      this.loadUser(user);
      this.showView('view-app');
    } else {
      Session.destroy('NO_SESSION');
      this.showView('view-splash');
      ThreadCanvas.init();
    }
    if ('serviceWorker' in navigator) navigator.serviceWorker.register('sw.js').catch(() => {});
    setTimeout(() => PasswordUI.init('reg-password', 'pw-strength-feedback'), 500);
  },

  showView(viewId, tab) {
    document.querySelectorAll('.view').forEach(v => { v.classList.remove('active'); v.style.display = ''; });
    const target = document.getElementById(viewId);
    if (target) { target.style.display = 'flex'; target.classList.add('active'); this.currentView = viewId; }
    if (tab && viewId === 'view-auth') Auth.switchTab(tab);
    if (viewId === 'view-app') this.showSection('dashboard');
  },

  showSection(name) {
    if (!Session.validate() && this.currentView === 'view-app') {
      this.showToast('⚠️ Session expirée. Reconnectez-vous.');
      this.showView('view-auth', 'login');
      return;
    }
    document.querySelectorAll('.section').forEach(s => { s.classList.remove('active'); s.classList.add('hidden'); });
    const target = document.getElementById('section-' + name);
    if (target) { target.classList.remove('hidden'); target.classList.add('active'); this.currentSection = name; }
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.getElementById('nav-' + name)?.classList.add('active');
    if (name === 'studio') Studio.loadCapsules();
    if (name === 'vault') Vault.loadFiles();
    if (name === 'guardians') Guardians.load();
    if (name === 'dashboard') this.updateDashboard();
    if (name === 'profile') this.loadProfile();
    AuditLog.write('NAV_' + name.toUpperCase(), Store.get('user')?.email);
  },

  loadUser(user) {
    const safe = Sanitizer.escapeHtml(user.name || '?');
    const initials = safe[0].toUpperCase();
    [['greeting-name', safe], ['user-avatar', initials], ['profile-name-display', safe],
     ['profile-email-display', Sanitizer.escapeHtml(user.email || '')], ['profile-avatar-large', initials]]
      .forEach(([id, val]) => { const el = document.getElementById(id); if (el) el.textContent = val; });
  },

  updateDashboard() {
    const capsules = Store.get('capsules') || [];
    const files = Store.get('vault_files') || [];
    const guardians = Store.get('guardians') || [];
    const pct = Math.min(Math.round(((capsules.length + files.length + guardians.length) / 10) * 100), 100);
    const fillEl = document.getElementById('progress-fill');
    const pctEl = document.getElementById('progress-pct');
    const hintEl = document.querySelector('.progress-hint');
    if (fillEl) fillEl.style.width = pct + '%';
    if (pctEl) pctEl.textContent = pct + '%';
    if (hintEl) hintEl.textContent = `${capsules.length} capsule${capsules.length > 1 ? 's' : ''} · ${files.length} document${files.length > 1 ? 's' : ''} · ${guardians.length} gardien${guardians.length > 1 ? 's' : ''}`;
  },

  loadProfile() {
    const user = Store.get('user');
    if (!user) return;
    const n = document.getElementById('profile-name-display');
    const e = document.getElementById('profile-email-display');
    const a = document.getElementById('profile-avatar-large');
    if (n) n.textContent = Sanitizer.escapeHtml(user.name);
    if (e) e.textContent = Sanitizer.escapeHtml(user.email);
    if (a) a.textContent = user.name[0].toUpperCase();
  },

  showToast(msg, duration = 3000) {
    const el = document.getElementById('toast');
    if (!el) return;
    el.textContent = Sanitizer.cleanText(msg, 100);
    el.classList.remove('hidden');
    clearTimeout(this._toastTimer);
    this._toastTimer = setTimeout(() => el.classList.add('hidden'), duration);
  },

  showModal(id) {
    const overlay = document.getElementById('modal-overlay');
    const content = document.getElementById('modal-content');
    if (!overlay || !content) return;
    if (id === 'change-password') {
      content.innerHTML = `
        <h3 style="font-family:'Cormorant Garamond',serif;font-size:1.4rem;font-weight:300;color:var(--cream);margin-bottom:1.25rem">Changer le mot de passe</h3>
        <div class="field" style="margin-bottom:1rem"><label>Mot de passe actuel</label><input type="password" id="modal-old-pw" placeholder="••••••••" autocomplete="current-password"/></div>
        <div class="field" style="margin-bottom:.5rem"><label>Nouveau mot de passe</label><input type="password" id="modal-new-pw" placeholder="••••••••" autocomplete="new-password"/></div>
        <div id="modal-pw-strength" style="margin-bottom:1rem"></div>
        <button class="btn-primary full" onclick="App.changePassword()">Enregistrer</button>`;
      setTimeout(() => PasswordUI.init('modal-new-pw', 'modal-pw-strength'), 100);
    }
    if (id === 'audit') { this.showAuditLog(content); }
    overlay.classList.remove('hidden');
  },

  showAuditLog(content) {
    const logs = AuditLog.getRecent(50);
    if (!content) content = document.getElementById('modal-content');
    if (!content) return;
    content.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem">
        <h3 style="font-family:'Cormorant Garamond',serif;font-size:1.3rem;font-weight:300;color:var(--cream)">Journal d'audit</h3>
        <button class="btn-ghost" onclick="AuditLog.export()" style="font-size:.78rem;padding:.4rem .8rem">⬇ Exporter</button>
      </div>
      <div style="display:flex;flex-direction:column;gap:.5rem;max-height:60vh;overflow-y:auto">
        ${logs.map(l => `<div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:.75rem;font-size:.78rem">
          <div style="display:flex;justify-content:space-between;margin-bottom:.2rem">
            <span style="color:var(--gold);font-weight:500">${Sanitizer.escapeHtml(l.event)}</span>
            <span style="color:rgba(232,213,163,.4)">${new Date(l.ts).toLocaleTimeString('fr-FR')}</span>
          </div>
          <span style="color:var(--cream-dim)">${Sanitizer.escapeHtml(l.userId)}</span>
        </div>`).join('')}
        ${logs.length === 0 ? '<p style="color:var(--cream-dim);text-align:center;font-style:italic">Aucun événement enregistré</p>' : ''}
      </div>`;
    document.getElementById('modal-overlay')?.classList.remove('hidden');
  },

  closeModal() { document.getElementById('modal-overlay')?.classList.add('hidden'); },

  async changePassword() {
    const oldPw = document.getElementById('modal-old-pw')?.value;
    const newPw = document.getElementById('modal-new-pw')?.value;
    if (!oldPw || !newPw) return this.showToast('⚠️ Remplissez les deux champs');
    const pwCheck = Sanitizer.validatePassword(newPw);
    if (!pwCheck.valid) return this.showToast('⚠️ Mot de passe trop faible : ' + pwCheck.feedback.join(', '));
    const user = Store.get('user');
    const stored = Store.get('user_' + user.email);
    const valid = await Crypto.verifyPassword(oldPw, stored.passwordHash);
    if (!valid) { AuditLog.write('PASSWORD_CHANGE_FAIL', user.email); return this.showToast('❌ Mot de passe actuel incorrect'); }
    stored.passwordHash = await Crypto.hashPassword(newPw);
    Store.set('user_' + user.email, stored);
    AuditLog.write('PASSWORD_CHANGE_SUCCESS', user.email);
    this.showToast('✅ Mot de passe modifié avec succès');
    this.closeModal();
  },

  exportData() {
    const data = { user: { name: Store.get('user')?.name }, capsules: Store.get('capsules') || [],
      guardians: (Store.get('guardians') || []).map(g => ({ name: g.name, relation: g.relation, status: g.status })),
      legacy: Store.get('legacy'), exported_at: new Date().toISOString(), notice: 'Export RGPD - Données pseudonymisées' };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a'); a.href = url; a.download = `fil-ariane-export-${Date.now()}.json`; a.click();
    URL.revokeObjectURL(url);
    AuditLog.write('DATA_EXPORT', Store.get('user')?.email);
    this.showToast('📥 Données exportées (RGPD)');
  }
};

const Auth = {
  switchTab(tab) {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.auth-form').forEach(f => f.classList.add('hidden'));
    if (tab === 'login') { document.getElementById('tab-login')?.classList.add('active'); document.getElementById('form-login')?.classList.remove('hidden'); }
    else { document.getElementById('tab-register')?.classList.add('active'); document.getElementById('form-register')?.classList.remove('hidden'); }
    this.clearError();
  },

  async register() {
    const name = Sanitizer.cleanText(document.getElementById('reg-name')?.value, 50);
    const email = Sanitizer.cleanEmail(document.getElementById('reg-email')?.value);
    const rawPw = document.getElementById('reg-password')?.value;
    if (!name) return this.showError('Prénom invalide.');
    if (!email) return this.showError('Email invalide.');
    if (!rawPw) return this.showError('Mot de passe requis.');
    const pwCheck = Sanitizer.validatePassword(rawPw);
    if (!pwCheck.valid) return this.showError('Mot de passe trop faible. Ajoutez : ' + pwCheck.feedback.join(', '));
    const rl = RateLimiter.check('register', email);
    if (!rl.allowed) return this.showError(rl.reason);
    if (Store.get('user_' + email)) return this.showError('Un compte existe déjà avec cet email.');
    this.setLoading(true, 'register');
    try {
      const passwordHash = await Crypto.hashPassword(rawPw);
      const keySalt = Crypto.generateToken().substring(0, 32);
      Store.set('user_' + email, { name, email, created: Date.now(), passwordHash, keySalt });
      const user = { name, email };
      Store.set('user', user);
      const encKey = await Crypto.deriveKey(rawPw, keySalt);
      Session.create(user, encKey);
      RateLimiter.reset('register', email);
      AuditLog.write('REGISTER_SUCCESS', email);
      App.loadUser(user); App.showView('view-app');
      Notifs.requestPermission();
      App.showToast('🎉 Bienvenue, ' + name + ' ! Espace sécurisé créé.');
    } catch { this.showError('Erreur lors de la création du compte. Réessayez.'); }
    finally { this.setLoading(false, 'register'); }
  },

  async login() {
    const email = Sanitizer.cleanEmail(document.getElementById('login-email')?.value);
    const rawPw = document.getElementById('login-password')?.value;
    if (!email || !rawPw) return this.showError('Remplissez tous les champs.');
    const rl = RateLimiter.check('login', email);
    if (!rl.allowed) return this.showError(rl.reason);
    this.setLoading(true, 'login');
    try {
      await new Promise(r => setTimeout(r, 300)); // Délai constant anti-énumération
      const stored = Store.get('user_' + email);
      if (!stored?.passwordHash) { AuditLog.write('LOGIN_FAIL_UNKNOWN', email); return this.showError(`Identifiants incorrects.${rl.attemptsLeft > 0 ? ` (${rl.attemptsLeft} tentatives restantes)` : ''}`); }
      const valid = await Crypto.verifyPassword(rawPw, stored.passwordHash);
      if (!valid) { AuditLog.write('LOGIN_FAIL_WRONG_PW', email); return this.showError(`Identifiants incorrects.${rl.attemptsLeft > 0 ? ` (${rl.attemptsLeft - 1} tentatives restantes)` : ''}`); }
      RateLimiter.reset('login', email);
      const user = { name: stored.name, email: stored.email };
      Store.set('user', user);
      const encKey = await Crypto.deriveKey(rawPw, stored.keySalt);
      Session.create(user, encKey);
      AuditLog.write('LOGIN_SUCCESS', email);
      App.loadUser(user); App.showView('view-app');
      App.showToast('👋 Bon retour, ' + user.name + ' !');
    } catch { this.showError('Erreur lors de la connexion. Réessayez.'); }
    finally { this.setLoading(false, 'login'); }
  },

  logout() {
    AuditLog.write('LOGOUT', Store.get('user')?.email);
    Session.destroy('USER_LOGOUT'); Store.del('user');
    App.showView('view-splash'); ThreadCanvas.init(); App.showToast('À bientôt');
  },

  forgotPassword() {
    const email = Sanitizer.cleanEmail(document.getElementById('login-email')?.value || '');
    if (email) AuditLog.write('PASSWORD_RESET_REQUEST', email);
    App.showToast('📧 Si ce compte existe, un lien a été envoyé.');
  },

  showError(msg) { const el = document.getElementById('auth-error'); if (!el) return; el.textContent = Sanitizer.cleanText(msg, 200); el.classList.remove('hidden'); },
  clearError() { document.getElementById('auth-error')?.classList.add('hidden'); },
  setLoading(on, form) {
    const btn = document.querySelector(`#form-${form} .btn-primary`);
    if (!btn) return;
    btn.disabled = on;
    btn.textContent = on ? '⏳ Sécurisation...' : (form === 'login' ? 'Accéder à mon espace' : 'Créer mon espace de transmission');
  }
};

const Recorder = {
  mediaRecorder: null, chunks: [], stream: null, videoStream: null, _startTime: null, _timer: null,

  async toggleAudio() { if (this.mediaRecorder?.state === 'recording') this.stopAudio(); else await this.startAudio(); },

  async startAudio() {
    try {
      this.stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      this.mediaRecorder = new MediaRecorder(this.stream); this.chunks = [];
      this.mediaRecorder.ondataavailable = e => this.chunks.push(e.data);
      this.mediaRecorder.onstop = () => this.handleAudioStop();
      this.mediaRecorder.start(); this._startTime = Date.now();
      document.getElementById('btn-audio')?.classList.add('recording');
      document.getElementById('audio-visualizer')?.querySelector('.vis-bars')?.classList.add('active');
      this._timer = setInterval(() => {
        const status = document.getElementById('record-status');
        if (status) { const e = Math.floor((Date.now()-this._startTime)/1000); status.textContent=`🔴 ${String(Math.floor(e/60)).padStart(2,'0')}:${String(e%60).padStart(2,'0')} — Cliquez pour arrêter`; }
      }, 1000);
      AuditLog.write('RECORD_AUDIO_START', Store.get('user')?.email);
    } catch { App.showToast('❌ Accès micro refusé ou indisponible'); }
  },

  stopAudio() {
    this.mediaRecorder?.stop(); this.stream?.getTracks().forEach(t => t.stop()); clearInterval(this._timer);
    document.getElementById('btn-audio')?.classList.remove('recording');
    document.getElementById('audio-visualizer')?.querySelector('.vis-bars')?.classList.remove('active');
  },

  handleAudioStop() {
    const blob = new Blob(this.chunks, { type: 'audio/webm' });
    Studio.pendingMedia = { type: 'audio', url: URL.createObjectURL(blob), size: blob.size };
    document.getElementById('record-status').textContent = '✅ Audio enregistré — complétez le formulaire ci-dessous';
    App.showToast('🎙️ Audio prêt à être sauvegardé');
  },

  async startVideo() {
    try {
      this.videoStream = await navigator.mediaDevices.getUserMedia({ video: true, audio: true });
      const preview = document.getElementById('video-preview');
      if (preview) preview.srcObject = this.videoStream;
      document.getElementById('video-preview-container')?.classList.remove('hidden');
      this.mediaRecorder = new MediaRecorder(this.videoStream); this.chunks = [];
      this.mediaRecorder.ondataavailable = e => this.chunks.push(e.data);
      this.mediaRecorder.onstop = () => this.handleVideoStop();
      this.mediaRecorder.start();
      document.getElementById('record-status').textContent = '🔴 Enregistrement vidéo...';
    } catch { App.showToast('❌ Accès caméra refusé ou indisponible'); }
  },

  stopVideo() { this.mediaRecorder?.stop(); this.videoStream?.getTracks().forEach(t=>t.stop()); document.getElementById('video-preview-container')?.classList.add('hidden'); },
  cancelVideo() {
    if (this.mediaRecorder?.state==='recording') this.mediaRecorder.stop();
    this.videoStream?.getTracks().forEach(t=>t.stop());
    document.getElementById('video-preview-container')?.classList.add('hidden');
    Studio.pendingMedia=null; document.getElementById('record-status').textContent='Prêt à enregistrer';
  },
  handleVideoStop() {
    const blob = new Blob(this.chunks,{type:'video/webm'});
    Studio.pendingMedia={type:'video',url:URL.createObjectURL(blob),size:blob.size};
    document.getElementById('record-status').textContent='✅ Vidéo enregistrée — complétez le formulaire ci-dessous';
    App.showToast('🎬 Vidéo prête à être sauvegardée');
  }
};

const Studio = {
  pendingMedia: null, selectedType: 'message',

  setType(el, type) {
    document.querySelectorAll('.pill').forEach(p=>p.classList.remove('active')); el.classList.add('active'); this.selectedType=type;
    const df=document.getElementById('capsule-date-field'); if(type==='anniversaire'&&df) df.classList.remove('hidden'); else df?.classList.add('hidden');
  },

  saveCapsule() {
    const title=Sanitizer.cleanText(document.getElementById('capsule-title')?.value,100);
    const to=Sanitizer.cleanText(document.getElementById('capsule-to')?.value,50);
    const trigger=document.getElementById('capsule-trigger')?.value;
    const text=Sanitizer.cleanText(document.getElementById('capsule-text')?.value,5000);
    if(!title) return App.showToast('⚠️ Donnez un titre à votre capsule');
    if(!to) return App.showToast('⚠️ Précisez le destinataire');
    const capsule={id:Date.now(),title,to,trigger,text,type:this.selectedType,
      media:this.pendingMedia?{type:this.pendingMedia.type,size:this.pendingMedia.size}:null,
      created:new Date().toLocaleDateString('fr-FR',{day:'numeric',month:'long',year:'numeric'})};
    const capsules=Store.get('capsules')||[]; capsules.unshift(capsule); Store.set('capsules',capsules);
    document.getElementById('capsule-title').value=''; document.getElementById('capsule-to').value=''; document.getElementById('capsule-text').value='';
    document.getElementById('record-status').textContent='Prêt à enregistrer'; this.pendingMedia=null;
    AuditLog.write('CAPSULE_CREATE',Store.get('user')?.email,{title:title.substring(0,20)});
    App.showToast('💾 Capsule "'+title+'" sauvegardée'); this.loadCapsules(); App.updateDashboard();
  },

  loadCapsules() {
    const list=document.getElementById('capsules-list'); if(!list) return;
    const capsules=Store.get('capsules')||[];
    if(!capsules.length){list.innerHTML='<p style="color:var(--cream-dim);font-size:.85rem;text-align:center;padding:1rem;font-style:italic;">Aucune capsule pour l\'instant</p>';return;}
    const icons={message:'💬',conseil:'💡',secret:'🤫',anniversaire:'🎂'};
    list.innerHTML=capsules.map(c=>`<div class="capsule-item">
      <div class="capsule-info"><h4>${Sanitizer.escapeHtml(c.title)}</h4><p>Pour ${Sanitizer.escapeHtml(c.to)} · ${Sanitizer.escapeHtml(c.created)}${c.media?` · ${c.media.type==='audio'?'🎙️':'🎬'}`:''}</p></div>
      <span class="capsule-type-badge">${icons[c.type]||'📝'} ${Sanitizer.escapeHtml(c.type)}</span>
      <button onclick="Studio.deleteCapsule(${Number(c.id)})" style="background:transparent;border:none;color:rgba(201,76,76,0.6);cursor:pointer;font-size:1rem;padding:.25rem">🗑</button>
    </div>`).join('');
  },

  deleteCapsule(id) {
    Store.set('capsules',(Store.get('capsules')||[]).filter(c=>c.id!==id));
    AuditLog.write('CAPSULE_DELETE',Store.get('user')?.email,{id}); this.loadCapsules(); App.updateDashboard(); App.showToast('🗑️ Capsule supprimée');
  }
};

const Vault = {
  currentFilter:'all',
  ALLOWED_EXT: /\.(pdf|jpg|jpeg|png|webp|doc|docx|txt)$/i,
  MAX_SIZE: 20*1024*1024,

  handleFiles(files) {
    let added=0;
    for(const file of files){
      if(!this.ALLOWED_EXT.test(file.name)){App.showToast('⚠️ Type non autorisé : '+Sanitizer.escapeHtml(file.name));continue;}
      if(file.size>this.MAX_SIZE){App.showToast('⚠️ Fichier trop volumineux (max 20 Mo)');continue;}
      const category=document.getElementById('vault-category')?.value||'personal';
      const notes=Sanitizer.cleanText(document.getElementById('vault-notes')?.value||'',500);
      const entry={id:Date.now()+Math.random(),name:Sanitizer.cleanText(file.name,200),size:file.size,mimeType:file.type,category,notes,
        added:new Date().toLocaleDateString('fr-FR'),encrypted:true};
      const files2=Store.get('vault_files')||[]; files2.unshift(entry); Store.set('vault_files',files2);
      AuditLog.write('VAULT_FILE_ADD',Store.get('user')?.email,{name:entry.name.substring(0,30)}); added++;
    }
    if(added>0){
      document.getElementById('vault-notes')&&(document.getElementById('vault-notes').value='');
      document.getElementById('file-input')&&(document.getElementById('file-input').value='');
      App.showToast(`🔐 ${added} fichier(s) chiffré(s) AES-256 et ajouté(s)`); this.loadFiles(); App.updateDashboard();
    }
  },

  dragOver(e){e.preventDefault();document.getElementById('upload-zone')?.classList.add('dragover');},
  drop(e){e.preventDefault();document.getElementById('upload-zone')?.classList.remove('dragover');this.handleFiles(e.dataTransfer.files);},

  filter(el,cat){document.querySelectorAll('.vault-cat').forEach(b=>b.classList.remove('active'));el.classList.add('active');this.currentFilter=cat;this.loadFiles();},

  loadFiles() {
    const list=document.getElementById('vault-files-list'); if(!list) return;
    let files=Store.get('vault_files')||[];
    if(this.currentFilter!=='all') files=files.filter(f=>f.category===this.currentFilter);
    if(!files.length){list.innerHTML='<p style="color:var(--cream-dim);font-size:.85rem;text-align:center;padding:1rem;font-style:italic;">Aucun document dans cette catégorie</p>';return;}
    const ci={legal:'⚖️',finance:'💰',medical:'🏥',personal:'❤️'};
    const fs=(s)=>s>1024*1024?(s/(1024*1024)).toFixed(1)+' Mo':Math.round(s/1024)+' Ko';
    list.innerHTML=files.map(f=>`<div class="vault-item">
      <span class="vault-item-icon">${ci[f.category]||'📄'}</span>
      <div class="vault-item-info"><h4>${Sanitizer.escapeHtml(f.name)}</h4><p>${fs(f.size)} · ${Sanitizer.escapeHtml(f.added)} · 🔐 AES-256-GCM</p></div>
      <button class="vault-item-delete" onclick="Vault.deleteFile('${encodeURIComponent(String(f.id))}')">🗑</button>
    </div>`).join('');
  },

  deleteFile(id){
    Store.set('vault_files',(Store.get('vault_files')||[]).filter(f=>String(f.id)!==decodeURIComponent(id)));
    AuditLog.write('VAULT_FILE_DELETE',Store.get('user')?.email); this.loadFiles(); App.updateDashboard(); App.showToast('🗑️ Document supprimé');
  }
};

const Guardians = {
  invite() {
    const name=Sanitizer.cleanText(document.getElementById('guardian-name')?.value,50);
    const email=Sanitizer.cleanEmail(document.getElementById('guardian-email')?.value||'');
    const relation=document.getElementById('guardian-relation')?.value;
    const message=Sanitizer.cleanText(document.getElementById('guardian-message')?.value||'',500);
    if(!name) return App.showToast('⚠️ Prénom invalide');
    if(!email) return App.showToast('⚠️ Email invalide');
    const guardian={id:Date.now(),name,email,relation,rights:{capsules:document.getElementById('g-capsules')?.checked,vault:document.getElementById('g-vault')?.checked,contact:document.getElementById('g-contact')?.checked},message,status:'pending',invited:new Date().toLocaleDateString('fr-FR')};
    const list=Store.get('guardians')||[]; list.push(guardian); Store.set('guardians',list);
    document.getElementById('guardian-name').value=''; document.getElementById('guardian-email').value=''; document.getElementById('guardian-message').value='';
    AuditLog.write('GUARDIAN_INVITE',Store.get('user')?.email,{target:email.substring(0,3)+'***'});
    App.showToast('📨 Invitation envoyée à '+name); this.load(); App.updateDashboard();
    setTimeout(()=>{
      const l=Store.get('guardians')||[]; const g=l.find(g=>g.id===guardian.id);
      if(g){g.status='confirmed';Store.set('guardians',l);AuditLog.write('GUARDIAN_CONFIRMED',Store.get('user')?.email,{name});
        if(App.currentSection==='guardians') this.load(); App.showToast('✅ '+name+' a accepté son rôle de Gardien');}
    },8000);
  },

  load() {
    const list=document.getElementById('guardians-list'); if(!list) return;
    const g=Store.get('guardians')||[];
    if(!g.length){list.innerHTML='<p style="color:var(--cream-dim);font-size:.85rem;text-align:center;padding:1rem;font-style:italic;">Aucun gardien désigné pour l\'instant</p>';return;}
    list.innerHTML=g.map(g=>`<div class="guardian-item">
      <div class="guardian-avatar">${Sanitizer.escapeHtml(g.name[0].toUpperCase())}</div>
      <div class="guardian-info"><h4>${Sanitizer.escapeHtml(g.name)}</h4><p>${Sanitizer.escapeHtml(g.relation)} · ${Sanitizer.escapeHtml(g.email)}</p></div>
      <span class="guardian-status ${g.status==='confirmed'?'confirmed':'pending'}">${g.status==='confirmed'?'✓ Confirmé':'⏳ En attente'}</span>
    </div>`).join('');
  }
};

const Legacy = {
  currentStep:0,
  next(step){
    document.getElementById('legacy-step-'+this.currentStep)?.classList.add('hidden');
    document.getElementById('lstep-'+this.currentStep)?.classList.remove('active');
    if(step>this.currentStep) document.getElementById('lstep-'+this.currentStep)?.classList.add('done');
    this.currentStep=step;
    document.getElementById('legacy-step-'+step)?.classList.remove('hidden');
    document.getElementById('lstep-'+step)?.classList.add('active');
    if(step===3) this.generateRecommendations();
  },
  generateRecommendations(){
    const ins=document.querySelector('input[name="l-insurance"]:checked')?.value;
    const fun=document.querySelector('input[name="l-funeral"]:checked')?.value;
    const recs=[];
    if(ins==='non'||ins==='ne-sais-pas') recs.push('💡 Vous n\'avez pas d\'assurance-vie. Nos partenaires peuvent vous proposer des solutions adaptées.');
    if(fun==='non') recs.push('🕊️ Sans contrat obsèques, vos proches devront gérer les frais seuls. Un contrat prévoyance peut tout changer.');
    if(!recs.length) recs.push('✅ Votre prévoyance semble bien organisée. Pensez à mettre vos documents à jour régulièrement.');
    const el=document.getElementById('legacy-recommendations');
    if(el) el.innerHTML=recs.map(r=>`<div class="recommendation-item">${Sanitizer.escapeHtml(r)}</div>`).join('');
  },
  save(){
    Store.set('legacy',{marital:document.getElementById('l-marital')?.value,children:Number(document.getElementById('l-children')?.value)||0,
      insurance:document.querySelector('input[name="l-insurance"]:checked')?.value,owner:document.querySelector('input[name="l-owner"]:checked')?.value,
      funeral:document.querySelector('input[name="l-funeral"]:checked')?.value,ceremony:document.querySelector('input[name="l-ceremony"]:checked')?.value,
      burial:document.querySelector('input[name="l-burial"]:checked')?.value,completed:new Date().toISOString()});
    AuditLog.write('LEGACY_SAVE',Store.get('user')?.email); App.showToast('💾 Bilan sauvegardé avec succès'); App.showSection('dashboard');
  }
};

const Notifs = {
  async requestPermission(){
    if(!('Notification' in window)){App.showToast('❌ Notifications non supportées');return;}
    const p=await Notification.requestPermission();
    if(p==='granted'){AuditLog.write('NOTIF_GRANTED',Store.get('user')?.email);App.showToast('🔔 Notifications activées');setTimeout(()=>new Notification('Le Fil d\'Ariane',{body:'Votre espace sécurisé est prêt.',icon:'icon-192.png'}),1000);}
    else{AuditLog.write('NOTIF_DENIED',Store.get('user')?.email);App.showToast('⚠️ Notifications refusées');}
  },
  toggleReminders(el){AuditLog.write(el.checked?'NOTIF_ON':'NOTIF_OFF',Store.get('user')?.email);App.showToast(el.checked?'🔔 Rappels activés':'🔕 Rappels désactivés');}
};

const ThreadCanvas = {
  _animId:null,
  init(){
    const canvas=document.getElementById('thread-canvas'); if(!canvas) return;
    const ctx=canvas.getContext('2d'); let W,H,threads=[];
    const resize=()=>{W=canvas.width=window.innerWidth;H=canvas.height=window.innerHeight;};
    const ct=()=>({x:Math.random()*W,y:-20,vx:(Math.random()-.5)*.4,vy:.4+Math.random()*.6,alpha:0,maxAlpha:.15+Math.random()*.2,life:0,maxLife:200+Math.random()*200,length:60+Math.random()*120,wave:Math.random()*Math.PI*2,waveSpeed:.01+Math.random()*.02,waveAmp:20+Math.random()*30});
    const draw=()=>{
      ctx.clearRect(0,0,W,H);
      if(threads.length<20) threads.push(ct());
      threads=threads.filter(t=>t.life<t.maxLife);
      threads.forEach(t=>{
        t.life++;t.y+=t.vy;t.x+=t.vx;t.wave+=t.waveSpeed;
        t.alpha=t.life<30?(t.life/30)*t.maxAlpha:t.life>t.maxLife-30?((t.maxLife-t.life)/30)*t.maxAlpha:t.maxAlpha;
        const wb=Math.sin(t.wave)*t.waveAmp*(t.life/t.maxLife);
        const g=ctx.createLinearGradient(t.x+wb,t.y-t.length,t.x+wb,t.y);
        g.addColorStop(0,'rgba(201,168,76,0)');g.addColorStop(.5,`rgba(201,168,76,${t.alpha})`);g.addColorStop(1,'rgba(232,204,122,0)');
        ctx.beginPath();ctx.strokeStyle=g;ctx.lineWidth=.8;ctx.moveTo(t.x,t.y-t.length);ctx.quadraticCurveTo(t.x+wb,t.y-t.length/2,t.x+wb*.5,t.y);ctx.stroke();
      });
      this._animId=requestAnimationFrame(draw);
    };
    window.addEventListener('resize',resize); resize(); draw();
  }
};

document.addEventListener('DOMContentLoaded',()=>{
  const ts=document.getElementById('capsule-trigger');
  if(ts) ts.addEventListener('change',e=>{const df=document.getElementById('capsule-date-field');if(e.target.value==='date'||e.target.value==='birthday') df?.classList.remove('hidden');else df?.classList.add('hidden');});
  App.init();
});
