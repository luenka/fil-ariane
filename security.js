/* ══════════════════════════════════════════════════════════
   LE FIL D'ARIANE — Module Sécurité Optimisé
══════════════════════════════════════════════════════════ */

'use strict';

const Crypto = {
  _buf2hex: (buf) => Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join(''),
  _hex2buf: (hex) => new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16))),
  _str2buf: (str) => new TextEncoder().encode(str),
  _buf2str: (buf) => new TextDecoder().decode(buf),
  _buf2b64: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))),
  _b642buf: (b64) => Uint8Array.from(atob(b64), c => c.charCodeAt(0)),

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
      const a = new Uint8Array(hash);
      const b = this._hex2buf(hashHex);
      if (a.length !== b.length) return false;
      let diff = 0;
      for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
      return diff === 0;
    } catch { return false; }
  },

  async deriveKey(password, saltHex) {
    const keyMaterial = await crypto.subtle.importKey(
      'raw', this._str2buf(password), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: this._hex2buf(saltHex), hash: 'SHA-256', iterations: 100000 },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  },

  async encrypt(plaintext, key) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = this._str2buf(plaintext);
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv }, key, encoded
    );
    return this._buf2b64(iv) + ':' + this._buf2b64(ciphertext);
  },

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

  generateToken() {
    return this._buf2hex(crypto.getRandomValues(new Uint8Array(32)));
  }
};

const Session = {
  SESSION_DURATION: 24 * 60 * 60 * 1000,
  IDLE_TIMEOUT: 30 * 60 * 1000,
  _idleTimer: null,
  _encKey: null,

  create(user, encKey) {
    const token = Crypto.generateToken();
    const session = {
      token,
      userId: user.email,
      expires: Date.now() + this.SESSION_DURATION,
      lastActivity: Date.now()
    };
    sessionStorage.setItem('fda_session', JSON.stringify(session));
    this._encKey = encKey;
    this._resetIdleTimer();
    AuditLog.write('SESSION_CREATE', user.email);
    return token;
  },

  validate() {
    try {
      const raw = sessionStorage.getItem('fda_session');
      if (!raw) return null;
      const session = JSON.parse(raw);
      if (Date.now() > session.expires) {
        this.destroy('EXPIRED');
        return null;
      }
      session.lastActivity = Date.now();
      sessionStorage.setItem('fda_session', JSON.stringify(session));
      return session;
    } catch { return null; }
  },

  destroy(reason = 'USER_LOGOUT') {
    const raw = sessionStorage.getItem('fda_session');
    if (raw) {
      try {
        const session = JSON.parse(raw);
        AuditLog.write('SESSION_DESTROY', session.userId, { reason });
      } catch {}
    }
    sessionStorage.removeItem('fda_session');
    this._encKey = null;
    clearTimeout(this._idleTimer);
  },

  getKey() { return this._encKey; },

  _resetIdleTimer() {
    clearTimeout(this._idleTimer);
    this._idleTimer = setTimeout(() => {
      this.destroy('IDLE_TIMEOUT');
      App.showToast('⏱️ Session expirée par inactivité.');
      App.showView('view-auth');
    }, this.IDLE_TIMEOUT);
  },

  touch() { if (this.validate()) this._resetIdleTimer(); }
};

const RateLimiter = {
  MAX_ATTEMPTS: 5,
  LOCKOUT_DURATION: 15 * 60 * 1000,

  check(action, identifier) {
    const key = `rl_${action}_${identifier}`;
    const raw = localStorage.getItem(key);
    let record = raw ? JSON.parse(raw) : { attempts: 0, firstAttempt: Date.now(), locked: false, lockedUntil: 0 };

    if (record.locked && Date.now() > record.lockedUntil) {
      record = { attempts: 0, firstAttempt: Date.now(), locked: false, lockedUntil: 0 };
    }

    if (record.locked) {
      const remaining = Math.ceil((record.lockedUntil - Date.now()) / 60000);
      return { allowed: false, reason: `Trop de tentatives. Réessayez dans ${remaining} min.` };
    }

    record.attempts++;
    if (record.attempts >= this.MAX_ATTEMPTS) {
      record.locked = true;
      record.lockedUntil = Date.now() + this.LOCKOUT_DURATION;
      AuditLog.write('RATE_LIMIT_TRIGGERED', identifier, { action, attempts: record.attempts });
    }
    localStorage.setItem(key, JSON.stringify(record));
    return { allowed: !record.locked, reason: record.locked ? `Compte bloqué temporairement.` : null };
  },

  reset(action, identifier) { localStorage.removeItem(`rl_${action}_${identifier}`); }
};

const Sanitizer = {
  escapeHtml(str) {
    if (typeof str !== 'string') return '';
    return str.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#x27;');
  },
  cleanText(str, maxLength = 1000) {
    if (typeof str !== 'string') return '';
    return str.replace(/<[^>]+>/g, '').trim().substring(0, maxLength);
  },
  cleanEmail(email) {
    if (typeof email !== 'string') return '';
    const cleaned = email.toLowerCase().trim();
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(cleaned) ? cleaned : '';
  },
  validatePassword(password) {
    const checks = {
      length: password.length >= 8,
      uppercase: /[A-Z]/.test(password),
      lowercase: /[a-z]/.test(password),
      number: /[0-9]/.test(password)
    };
    const score = Object.values(checks).filter(Boolean).length;
    const feedback = [];
    if (!checks.length) feedback.push('8 car. min');
    if (!checks.uppercase) feedback.push('1 majuscule');
    if (!checks.number) feedback.push('1 chiffre');
    return { valid: score === 4, score, feedback };
  }
};

const AuditLog = {
  write(event, userId = 'anonymous', meta = {}) {
    const entry = { ts: Date.now(), date: new Date().toISOString(), event, userId: userId.substring(0, 4) + '***', ...meta };
    try {
      const logs = JSON.parse(localStorage.getItem('fda_audit') || '[]');
      logs.unshift(entry);
      if (logs.length > 100) logs.length = 100;
      localStorage.setItem('fda_audit', JSON.stringify(logs));
    } catch {}
  }
};

const SecureStore = {
  async set(key, value) {
    const encKey = Session.getKey();
    if (!encKey) return;
    try {
      const encrypted = await Crypto.encrypt(JSON.stringify(value), encKey);
      localStorage.setItem('fda_sec_' + key, encrypted);
    } catch {}
  },
  async get(key) {
    const encKey = Session.getKey();
    const raw = localStorage.getItem('fda_sec_' + key);
    if (!raw || !encKey) return null;
    try {
      const decrypted = await Crypto.decrypt(raw, encKey);
      return decrypted ? JSON.parse(decrypted) : null;
    } catch { return null; }
  },
  del(key) { localStorage.removeItem('fda_sec_' + key); }
};
