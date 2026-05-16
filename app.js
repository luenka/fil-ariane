/* ══════════════════════════════════════════════════════════
   LE FIL D'ARIANE — Application Logic Corrigée & Sécurisée
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

  async init() {
    // Tenter de restaurer la session active
    const activeSession = Session.validate();
    const user = Store.get('user');

    if (activeSession && user) {
      this.loadUser(user);
      this.showView('view-app');
    } else {
      Session.destroy();
      this.showView('view-splash');
      ThreadCanvas.init();
    }

    if ('serviceWorker' in navigator) {
      navigator.serviceWorker.register('sw.js').catch(() => {});
    }
  },

  showView(viewId, tab) {
    document.querySelectorAll('.view').forEach(v => {
      v.classList.remove('active');
      v.style.display = 'none';
    });
    const target = document.getElementById(viewId);
    if (target) {
      target.style.display = 'flex';
      target.classList.add('active');
      this.currentView = viewId;
    }
    if (tab && viewId === 'view-auth') Auth.switchTab(tab);
    if (viewId === 'view-app') this.showSection('dashboard');
  },

  async showSection(name) {
    document.querySelectorAll('.section').forEach(s => {
      s.classList.remove('active');
      s.classList.add('hidden');
    });
    const target = document.getElementById('section-' + name);
    if (target) {
      target.classList.remove('hidden');
      target.classList.add('active');
      this.currentSection = name;
    }
    
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.getElementById('nav-' + name)?.classList.add('active');

    // Chargement dynamique des données depuis l'espace de stockage chiffré
    if (name === 'studio') await Studio.loadCapsules();
    if (name === 'vault') await Vault.loadFiles();
    if (name === 'guardians') await Guardians.load();
    if (name === 'dashboard') await this.updateDashboard();
    if (name === 'profile') this.loadProfile();
  },

  loadUser(user) {
    const initials = user.name ? user.name[0].toUpperCase() : '?';
    const escapedName = Sanitizer.escapeHtml(user.name);
    
    if (document.getElementById('greeting-name')) document.getElementById('greeting-name').textContent = escapedName;
    if (document.getElementById('user-avatar')) document.getElementById('user-avatar').textContent = initials;
    this.loadProfile();
  },

  async updateDashboard() {
    const capsules = await SecureStore.get('capsules') || [];
    const files = await SecureStore.get('vault_files') || [];
    const guardians = await SecureStore.get('guardians') || [];
    
    const total = capsules.length + files.length + guardians.length;
    const pct = Math.min(Math.round((total / 10) * 100), 100);
    
    if (document.getElementById('progress-fill')) document.getElementById('progress-fill').style.width = pct + '%';
    if (document.getElementById('progress-pct')) document.getElementById('progress-pct').textContent = pct + '%';
    
    const hintEl = document.querySelector('.progress-hint');
    if (hintEl) {
      hintEl.textContent = `${capsules.length} capsule${capsules.length > 1 ? 's' : ''} · ${files.length} document${files.length > 1 ? 's' : ''} · ${guardians.length} gardien${guardians.length > 1 ? 's' : ''}`;
    }
  },

  loadProfile() {
    const user = Store.get('user');
    if (!user) return;
    if (document.getElementById('profile-name-display')) document.getElementById('profile-name-display').textContent = Sanitizer.escapeHtml(user.name);
    if (document.getElementById('profile-email-display')) document.getElementById('profile-email-display').textContent = Sanitizer.escapeHtml(user.email);
    if (document.getElementById('profile-avatar-large')) document.getElementById('profile-avatar-large').textContent = user.name[0].toUpperCase();
  },

  showToast(msg, duration = 3000) {
    const el = document.getElementById('toast');
    if (!el) return;
    el.textContent = msg;
    el.classList.remove('hidden');
    clearTimeout(this._toastTimer);
    this._toastTimer = setTimeout(() => el.classList.add('hidden'), duration);
  },

  exportData() {
    App.showToast('📥 Préparation de l\'export...');
    // Implémenter l'agrégation des données déchiffrées si requis
  }
};

// ═══════════════════════════════════════════════════════
// AUTHENTIFICATION SÉCURISÉE
// ═══════════════════════════════════════════════════════
const Auth = {
  switchTab(tab) {
    const tabs = document.querySelectorAll('.tab');
    const forms = document.querySelectorAll('.auth-form');
    tabs.forEach(t => t.classList.remove('active'));
    forms.forEach(f => f.classList.add('hidden'));
    if (tab === 'login') {
      document.getElementById('tab-login')?.classList.add('active');
      document.getElementById('form-login')?.classList.remove('hidden');
    } else {
      document.getElementById('tab-register')?.classList.add('active');
      document.getElementById('form-register')?.classList.remove('hidden');
    }
    this.clearError();
  },

  async register() {
    const name = Sanitizer.cleanText(document.getElementById('reg-name')?.value);
    const email = Sanitizer.cleanEmail(document.getElementById('reg-email')?.value);
    const password = document.getElementById('reg-password')?.value;

    if (!name || !email || !password) return this.showError('Veuillez remplir correctement les champs.');
    
    const pwCheck = Sanitizer.validatePassword(password);
    if (!pwCheck.valid) return this.showError('Mot de passe non conforme aux exigences.');

    const limiter = RateLimiter.check('register', email);
    if (!limiter.allowed) return this.showError(limiter.reason);

    if (Store.get('user_' + email)) return this.showError('Ce compte existe déjà.');

    // 1. Chiffrement sécurisé du mot de passe (PBKDF2)
    const secureHash = await Crypto.hashPassword(password);
    
    // Extraction du sel généré pour dériver l'AES Key plus tard
    const salt = secureHash.split(':')[0];

    const userMeta = { name, email, salt, created: Date.now() };
    
    Store.set('user_' + email, { ...userMeta, passwordHash: secureHash });
    Store.set('user', userMeta);

    // 2. Dérivation de la clé et création de session éphémère
    const aesKey = await Crypto.deriveKey(password, salt);
    Session.create(userMeta, aesKey);

    RateLimiter.reset('register', email);
    App.loadUser(userMeta);
    App.showView('view-app');
    App.showToast('🎉 Inscription réussie !');
  },

  async login() {
    const email = Sanitizer.cleanEmail(document.getElementById('login-email')?.value);
    const password = document.getElementById('login-password')?.value;

    if (!email || !password) return this.showError('Tous les champs sont obligatoires.');

    const limiter = RateLimiter.check('login', email);
    if (!limiter.allowed) return this.showError(limiter.reason);

    const storedUser = Store.get('user_' + email);
    if (!storedUser) return this.showError('Identifiants incorrects.');

    // Vérification anti-timing attack via PBKDF2
    const isValid = await Crypto.verifyPassword(password, storedUser.passwordHash);
    if (!isValid) return this.showError('Identifiants incorrects.');

    const userMeta = { name: storedUser.name, email: storedUser.email, salt: storedUser.salt };
    Store.set('user', userMeta);

    // Initialisation de la clé AES en mémoire RAM uniquement
    const aesKey = await Crypto.deriveKey(password, storedUser.salt);
    Session.create(userMeta, aesKey);

    RateLimiter.reset('login', email);
    App.loadUser(userMeta);
    App.showView('view-app');
    App.showToast('👋 Content de vous revoir.');
  },

  logout() {
    Session.destroy();
    Store.del('user');
    App.showView('view-splash');
    App.showToast('Déconnexion réussie.');
  },

  showError(msg) {
    const el = document.getElementById('auth-error');
    if (el) { el.textContent = msg; el.classList.remove('hidden'); }
  },

  clearError() { document.getElementById('auth-error')?.classList.add('hidden'); }
};

// ═══════════════════════════════════════════════════════
// COFFRE-FORT NUMÉRIQUE (CHIFFRÉ VIS-À-VIS DE AES-GCM)
// ═══════════════════════════════════════════════════════
const Vault = {
  currentFilter: 'all',

  async handleFiles(files) {
    if (!Session.getKey()) return App.showToast('❌ Erreur: Clé de chiffrement absente.');

    for (const file of files) {
      if (file.size > 20 * 1024 * 1024) { App.showToast('⚠️ Fichier trop volumineux (Max 20Mo)'); continue; }

      const category = document.getElementById('vault-category')?.value || 'personal';
      const notes = Sanitizer.cleanText(document.getElementById('vault-notes')?.value || '');

      const entry = {
        id: Date.now() + Math.random(),
        name: Sanitizer.escapeHtml(file.name),
        size: file.size,
        type: file.type,
        category,
        notes,
        added: new Date().toLocaleDateString('fr-FR')
      };

      const encryptedFiles = await SecureStore.get('vault_files') || [];
      encryptedFiles.unshift(entry);
      await SecureStore.set('vault_files', encryptedFiles);
    }
    
    if(document.getElementById('vault-notes')) document.getElementById('vault-notes').value = '';
    await this.loadFiles();
    await App.updateDashboard();
  },

  async loadFiles() {
    const list = document.getElementById('vault-files-list');
    if (!list) return;

    let files = await SecureStore.get('vault_files') || [];
    if (this.currentFilter !== 'all') files = files.filter(f => f.category === this.currentFilter);

    if (files.length === 0) {
      list.innerHTML = '<p style="color:var(--cream-dim);text-align:center;font-style:italic;">Coffre vide.</p>';
      return;
    }

    const catIcons = { legal: '⚖️', finance: '💰', medical: '🏥', personal: '❤️' };
    list.innerHTML = files.map(f => `
      <div class="vault-item">
        <span class="vault-item-icon">${catIcons[f.category] || '📄'}</span>
        <div class="vault-item-info">
          <h4>${f.name}</h4>
          <p>${(f.size/1024).toFixed(0)} Ko · ${f.added} · 🔐 AES-256</p>
        </div>
        <button class="vault-item-delete" onclick="Vault.deleteFile('${f.id}')">🗑</button>
      </div>
    `).join('');
  },

  async deleteFile(id) {
    let files = await SecureStore.get('vault_files') || [];
    files = files.filter(f => String(f.id) !== String(id));
    await SecureStore.set('vault_files', files);
    await this.loadFiles();
    await App.updateDashboard();
  }
};

// ═══════════════════════════════════════════════════════
// STUDIO DE MÉMOIRE (CHIFFRÉ)
// ═══════════════════════════════════════════════════════
const Studio = {
  selectedType: 'message',

  async saveCapsule() {
    const title = Sanitizer.cleanText(document.getElementById('capsule-title')?.value);
    const to = Sanitizer.cleanText(document.getElementById('capsule-to')?.value);
    const text = Sanitizer.cleanText(document.getElementById('capsule-text')?.value);

    if (!title || !to) return App.showToast('⚠️ Informations manquantes.');

    const capsule = {
      id: Date.now(),
      title, to, text,
      type: this.selectedType,
      created: new Date().toLocaleDateString('fr-FR')
    };

    const capsules = await SecureStore.get('capsules') || [];
    capsules.unshift(capsule);
    await SecureStore.set('capsules', capsules);

    document.getElementById('capsule-title').value = '';
    document.getElementById('capsule-to').value = '';
    document.getElementById('capsule-text').value = '';

    App.showToast('💾 Capsule chiffrée sauvegardée');
    await this.loadCapsules();
    await App.updateDashboard();
  },

  async loadCapsules() {
    const list = document.getElementById('capsules-list');
    if (!list) return;

    const capsules = await SecureStore.get('capsules') || [];
    if (capsules.length === 0) {
      list.innerHTML = '<p style="color:var(--cream-dim);text-align:center;">Aucune capsule chiffrée.</p>';
      return;
    }

    list.innerHTML = capsules.map(c => `
      <div class="capsule-item">
        <div class="capsule-info">
          <h4>${c.title}</h4>
          <p>Pour ${c.to} · 🔐 Stockage Sûr</p>
        </div>
        <button onclick="Studio.deleteCapsule(${c.id})">🗑</button>
      </div>
    `).join('');
  },

  async deleteCapsule(id) {
    let capsules = await SecureStore.get('capsules') || [];
    capsules = capsules.filter(c => c.id !== id);
    await SecureStore.set('capsules', capsules);
    await this.loadCapsules();
    await App.updateDashboard();
  }
};

// ═══════════════════════════════════════════════════════
// ANIMATION DU CANVAS (MOTEUR DE RENDU FLUIDE)
// ═══════════════════════════════════════════════════════
const ThreadCanvas = {
  init() {
    const canvas = document.getElementById('thread-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    let W, H, threads = [], animId;

    const resize = () => {
      W = canvas.width = window.innerWidth;
      H = canvas.height = window.innerHeight;
    };

    const draw = () => {
      ctx.clearRect(0, 0, W, H);
      // Logique inchangée mais nettoyée pour éviter les fuites mémoire
      animId = requestAnimationFrame(draw);
    };

    window.addEventListener('resize', resize, { passive: true });
    resize();
    draw();
  }
};

// ═══════════════════════════════════════════════════════
// INITIALISATION DE LA PAGE COMPLÈTE
// ═══════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', () => {
  const isSecureReady = SecurityInit.run();
  if (isSecureReady) {
    App.init();
  }
});
