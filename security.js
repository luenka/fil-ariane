/* ══════════════════════════════════════════════════════════
   LE FIL D'ARIANE — Module Sécurité
   Stack : Web Crypto API (native) · PBKDF2 · AES-256-GCM
   Conformité : RGPD · ANSSI · ISO 27001 (principes)
══════════════════════════════════════════════════════════ */

'use strict';

// ═══════════════════════════════════════════════════════
// CRYPTO — Hachage & Chiffrement (Web Crypto API native)
// ═══════════════════════════════════════════════════════
const Crypto = {

  // ── Convertisseurs utilitaires
  _buf2hex: (buf) => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join(''),
  _hex2buf: (hex) => new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16))),
  _str2buf: (str) => new TextEncoder().encode(str),
  _buf2str: (buf) => new TextDecoder().decode(buf),
  _buf2b64: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))),
  _b642buf: (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0)),

  /**
   * Hache un mot de passe avec PBKDF2-SHA256
   * 310 000 itérations (recommandation OWASP 2024)
   * @returns {string} "salt:hash" en hex
   */
  async hashPassword(password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const keyMaterial = await crypto.subtle.importKey(
      'raw', this._str2buf(password), 'PBKDF2', false, ['deriveBits']
    );
    const hash = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', salt, hash: 'SHA-256', iterations: 310000 },
      keyMaterial, 256
    );
    return this._buf2hex(salt) + ':' + this._buf2hex(hash);
  },

  /**
   * Vérifie un mot de passe contre son hash PBKDF2
   * @returns {boolean}
   */
  async verifyPassword(password, storedHash) {
    try {
      const [saltHex, hashHex] = storedHash.split(':');
      if (!saltHex || !hashHex) return false;
      const salt = this._hex2buf(saltHex);
      const keyMaterial = await crypto.subtle.importKey(
        'raw', this._str2buf(password), 'PBKDF2', false, ['deriveBits']
      );
      const hash = await crypto.subtle.deriveBits(
        { name: 'PBKDF2', salt, hash: 'SHA-256', iterations: 310000 },
        keyMaterial, 256
      );
      // Comparaison en temps constant (anti timing-attack)
      const a = new Uint8Array(hash);
      const b = this._hex2buf(hashHex);
      if (a.length !== b.length) return false;
      let diff = 0;
      for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
      return diff === 0;
    } catch { return false; }
  },

  /**
   * Dérive une clé AES-256 depuis le mot de passe (pour chiffrer les données)
   * Utilisé pour chiffrer les capsules et documents en stockage local
   */
  async deriveKey(password, salt) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw', this._str2buf(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: this._hex2buf(salt), hash: 'SHA-256', iterations: 100000 },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  /**
   * Chiffre une chaîne avec AES-256-GCM
   * @returns {string} "iv:ciphertext" en base64
   */
  async encrypt(plaintext, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = this._str2buf(plaintext);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, key, encoded
    );
    return this._buf2b64(iv) + ':' + this._buf2b64(ciphertext);
  },

  /**
   * Déchiffre une chaîne AES-256-GCM
   * @returns {string|null}
   */
  async decrypt(encrypted, key) {
    try {
      const [ivB64, cipherB64] = encrypted.split(':');
      const iv = this._b642buf(ivB64);
      const ciphertext = this._b642buf(cipherB64);
      const plaintext = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv }, key, ciphertext
      );
      return this._buf2str(plaintext);
    } catch { return null; }
  },

  /**
   * Génère un token de session sécurisé (256 bits)
   */
  generateToken() {
    return this._buf2hex(crypto.getRandomValues(new Uint8Array(32)));
  },

  /**
   * Hash SHA-256 simple (pour identifier des données sans les exposer)
   */
  async sha256(data) {
    const hash = await crypto.subtle.digest('SHA-256', this._str2buf(data));
    return this._buf2hex(hash);
  }
};

// ═══════════════════════════════════════════════════════
// SESSION MANAGER — Tokens + Expiration
// ═══════════════════════════════════════════════════════
const Session = {
  SESSION_DURATION: 24 * 60 * 60 * 1000, // 24 heures
  IDLE_TIMEOUT: 30 * 60 * 1000,           // 30 min d'inactivité → déconnexion
  _idleTimer: null,
  _encKey: null, // Clé AES en mémoire (jamais stockée)

  /**
   * Crée une session après authentification réussie
   */
  create(user, encKey) {
    const token = Crypto.generateToken();
    const session = {
      token,
      userId: user.email,
      created: Date.now(),
      expires: Date.now() + this.SESSION_DURATION,
      lastActivity: Date.now()
    };
    // Stockage du token (pas le mot de passe, jamais)
    sessionStorage.setItem('fda_session', JSON.stringify(session));
    this._encKey = encKey; // Clé uniquement en mémoire RAM
    this._resetIdleTimer();
    AuditLog.write('SESSION_CREATE', user.email);
    return token;
  },

  /**
   * Valide la session courante
   * @returns {object|null} session ou null si invalide/expirée
   */
  validate() {
    try {
      const raw = sessionStorage.getItem('fda_session');
      if (!raw) return null;
      const session = JSON.parse(raw);
      if (!session.token || !session.expires) return null;
      if (Date.now() > session.expires) {
        this.destroy('EXPIRED');
        return null;
      }
      // Mise à jour de l'activité
      session.lastActivity = Date.now();
      sessionStorage.setItem('fda_session', JSON.stringify(session));
      return session;
    } catch { return null; }
  },

  /**
   * Détruit la session (logout)
   */
  destroy(reason = 'USER_LOGOUT') {
    const session = this._getSession();
    if (session) AuditLog.write('SESSION_DESTROY', session.userId, { reason });
    sessionStorage.removeItem('fda_session');
    this._encKey = null;
    clearTimeout(this._idleTimer);
  },

  /**
   * Retourne la clé de chiffrement en mémoire
   */
  getKey() { return this._encKey; },

  _getSession() {
    try { return JSON.parse(sessionStorage.getItem('fda_session')); } catch { return null; }
  },

  _resetIdleTimer() {
    clearTimeout(this._idleTimer);
    this._idleTimer = setTimeout(() => {
      this.destroy('IDLE_TIMEOUT');
      App.showToast('⏱️ Session expirée par inactivité. Reconnectez-vous.');
      App.showView('view-auth');
    }, this.IDLE_TIMEOUT);
  },

  // Réinitialiser le timer à chaque interaction
  touch() { if (this.validate()) this._resetIdleTimer(); }
};

// ═══════════════════════════════════════════════════════
// RATE LIMITER — Anti brute-force
// ═══════════════════════════════════════════════════════
const RateLimiter = {
  MAX_ATTEMPTS: 5,
  LOCKOUT_DURATION: 15 * 60 * 1000, // 15 minutes

  /**
   * Enregistre une tentative et retourne si l'action est autorisée
   */
  check(action, identifier) {
    const key = `rl_${action}_${identifier}`;
    const raw = localStorage.getItem(key);
    let record = raw ? JSON.parse(raw) : { attempts: 0, firstAttempt: Date.now(), locked: false, lockedUntil: 0 };

    // Débloquer si le délai est passé
    if (record.locked && Date.now() > record.lockedUntil) {
      record = { attempts: 0, firstAttempt: Date.now(), locked: false, lockedUntil: 0 };
    }

    if (record.locked) {
      const remaining = Math.ceil((record.lockedUntil - Date.now()) / 60000);
      return { allowed: false, reason: `Trop de tentatives. Réessayez dans ${remaining} min.` };
    }

    // Réinitialiser la fenêtre glissante (1h)
    if (Date.now() - record.firstAttempt > 3600000) {
      record = { attempts: 0, firstAttempt: Date.now(), locked: false, lockedUntil: 0 };
    }

    record.attempts++;
    if (record.attempts >= this.MAX_ATTEMPTS) {
      record.locked = true;
      record.lockedUntil = Date.now() + this.LOCKOUT_DURATION;
      AuditLog.write('RATE_LIMIT_TRIGGERED', identifier, { action, attempts: record.attempts });
    }
    localStorage.setItem(key, JSON.stringify(record));
    const remaining = this.MAX_ATTEMPTS - record.attempts;
    return {
      allowed: !record.locked,
      attemptsLeft: Math.max(0, remaining),
      reason: record.locked ? `Compte temporairement bloqué (${this.MAX_ATTEMPTS} tentatives).` : null
    };
  },

  /**
   * Réinitialise le compteur après succès
   */
  reset(action, identifier) {
    localStorage.removeItem(`rl_${action}_${identifier}`);
  }
};

// ═══════════════════════════════════════════════════════
// XSS SANITIZER — Protection injection
// ═══════════════════════════════════════════════════════
const Sanitizer = {
  /**
   * Échappe les caractères HTML dangereux
   */
  escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  },

  /**
   * Nettoie une entrée texte (supprime balises, scripts, etc.)
   */
  cleanText(str, maxLength = 1000) {
    if (typeof str !== 'string') return '';
    return str
      .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '')
      .replace(/<[^>]+>/g, '')
      .replace(/javascript:/gi, '')
      .replace(/on\w+\s*=/gi, '')
      .trim()
      .substring(0, maxLength);
  },

  /**
   * Valide et nettoie un email
   */
  cleanEmail(email) {
    if (typeof email !== 'string') return '';
    const cleaned = email.toLowerCase().trim().substring(0, 254);
    const re = /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
    return re.test(cleaned) ? cleaned : '';
  },

  /**
   * Valide la robustesse d'un mot de passe
   * Retourne { valid, score, feedback }
   */
  validatePassword(password) {
    const checks = {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      number: /[0-9]/.test(password),
      special: /[^A-Za-z0-9]/.test(password),
      noCommon: !['password', '123456', 'azerty', 'qwerty', 'motdepasse'].includes(password.toLowerCase())
    };
    const score = Object.values(checks).filter(Boolean).length;
    const feedback = [];
    if (!checks.length) feedback.push('8 caractères minimum');
    if (!checks.uppercase) feedback.push('une majuscule');
    if (!checks.number) feedback.push('un chiffre');
    if (!checks.special) feedback.push('un caractère spécial (!@#...)');
    if (!checks.noCommon) feedback.push('évitez les mots de passe courants');
    return { valid: score >= 4, score, feedback };
  }
};

// ═══════════════════════════════════════════════════════
// AUDIT LOG — Traçabilité des accès (RGPD)
// ═══════════════════════════════════════════════════════
const AuditLog = {
  MAX_ENTRIES: 500,

  /**
   * Enregistre un événement de sécurité
   */
  write(event, userId = 'anonymous', meta = {}) {
    const entry = {
      ts: Date.now(),
      date: new Date().toISOString(),
      event,
      userId: userId ? userId.substring(0, 3) + '***' : 'anon', // Pseudonymisation
      ua: navigator.userAgent.substring(0, 80),
      ...meta
    };
    try {
      const logs = JSON.parse(localStorage.getItem('fda_audit') || '[]');
      logs.unshift(entry);
      if (logs.length > this.MAX_ENTRIES) logs.length = this.MAX_ENTRIES;
      localStorage.setItem('fda_audit', JSON.stringify(logs));
    } catch {}
  },

  /**
   * Retourne les N derniers événements (pour l'admin)
   */
  getRecent(n = 20) {
    try {
      return JSON.parse(localStorage.getItem('fda_audit') || '[]').slice(0, n);
    } catch { return []; }
  },

  /**
   * Export des logs (droit d'accès RGPD)
   */
  export() {
    const logs = this.getRecent(this.MAX_ENTRIES);
    const blob = new Blob([JSON.stringify(logs, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-log-${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }
};

// ═══════════════════════════════════════════════════════
// SECURE STORE — Wrapper chiffré du localStorage
// ═══════════════════════════════════════════════════════
const SecureStore = {
  /**
   * Stocke une valeur chiffrée (nécessite une session active)
   */
  async set(key, value) {
    const encKey = Session.getKey();
    if (!encKey) {
      // Fallback non chiffré si pas de clé (données non sensibles)
      Store.set(key, value);
      return;
    }
    try {
      const plaintext = JSON.stringify(value);
      const encrypted = await Crypto.encrypt(plaintext, encKey);
      localStorage.setItem('fda_sec_' + key, encrypted);
    } catch { Store.set(key, value); }
  },

  /**
   * Récupère et déchiffre une valeur
   */
  async get(key) {
    const encKey = Session.getKey();
    const raw = localStorage.getItem('fda_sec_' + key);
    if (!raw || !encKey) return Store.get(key); // Fallback
    try {
      const decrypted = await Crypto.decrypt(raw, encKey);
      return decrypted ? JSON.parse(decrypted) : null;
    } catch { return Store.get(key); }
  },

  del(key) {
    localStorage.removeItem('fda_sec_' + key);
    Store.del(key);
  }
};

// ═══════════════════════════════════════════════════════
// CSP — Content Security Policy (runtime)
// ═══════════════════════════════════════════════════════
const CSP = {
  /**
   * Injecte une meta CSP (complément aux headers serveur)
   * En production, doit être dans les HTTP headers
   */
  inject() {
    const meta = document.createElement('meta');
    meta.httpEquiv = 'Content-Security-Policy';
    meta.content = [
      "default-src 'self'",
      "script-src 'self' 'unsafe-inline'", // unsafe-inline nécessaire pour PWA inline
      "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
      "font-src 'self' https://fonts.gstatic.com",
      "img-src 'self' data: blob:",
      "media-src 'self' blob:",
      "connect-src 'self'",
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "form-action 'self'"
    ].join('; ');
    document.head.insertBefore(meta, document.head.firstChild);
  }
};

// ═══════════════════════════════════════════════════════
// PASSWORD STRENGTH UI
// ═══════════════════════════════════════════════════════
const PasswordUI = {
  init(inputId, feedbackId) {
    const input = document.getElementById(inputId);
    const feedback = document.getElementById(feedbackId);
    if (!input || !feedback) return;
    input.addEventListener('input', () => {
      const result = Sanitizer.validatePassword(input.value);
      const colors = ['#c94c4c', '#c9844c', '#c9a84c', '#84c94c', '#4cc978'];
      const labels = ['Très faible', 'Faible', 'Moyen', 'Fort', 'Très fort'];
      const idx = Math.min(result.score - 1, 4);
      feedback.innerHTML = input.value.length === 0 ? '' : `
        <div class="pw-strength">
          <div class="pw-bars">
            ${Array.from({length: 5}, (_, i) => `<div class="pw-bar" style="background:${i <= idx ? colors[idx] : 'rgba(255,255,255,0.1)'}"></div>`).join('')}
          </div>
          <span style="color:${colors[Math.max(0,idx)]};font-size:.78rem">${labels[Math.max(0,idx)]}</span>
        </div>
        ${result.feedback.length ? `<p style="font-size:.75rem;color:var(--cream-dim);margin-top:.3rem">Ajouter : ${result.feedback.join(', ')}</p>` : ''}
      `;
    });
  }
};

// ═══════════════════════════════════════════════════════
// INIT SÉCURITÉ — Appelé au démarrage
// ═══════════════════════════════════════════════════════
const SecurityInit = {
  run() {
    // 1. Injecter la CSP
    CSP.inject();
    // 2. Protéger contre le clickjacking
    if (window.top !== window.self) {
      document.body.innerHTML = '<p style="color:red;padding:2rem">Accès non autorisé dans un iframe.</p>';
      return false;
    }
    // 3. Écouter l'activité pour le timer de session
    ['click', 'keypress', 'touchstart', 'scroll'].forEach(evt =>
      document.addEventListener(evt, () => Session.touch(), { passive: true })
    );
    // 4. Nettoyer en cas de fermeture (ne pas laisser la clé en mémoire)
    window.addEventListener('beforeunload', () => Session.destroy('TAB_CLOSE'));
    // 5. Log de démarrage
    AuditLog.write('APP_START', 'system', { version: '2.0-secure' });
    return true;
  }
};
