/**
 * HMAX-SECURE Main Library
 * Enterprise-grade military-level password hashing system
 */

import { randomBytes } from 'node:crypto';
import config from './config.js';
import secretManager from './secrets.js';
import hmac from './hmac.js';
import argon2 from './argon2.js';
import pbkdf2 from './pbkdf2.js';
import encoder from './encode.js';
import verifier from './verify.js';

/**
 * HMAX-SECURE Main Class
 */
class HMaxSecure {
  constructor() {
    this.initialized = false;
  }

  /**
   * Initialize the library with secrets
   */
  async initialize(secrets = {}) {
    if (secrets.currentSecret) {
      secretManager.setCurrentSecret(secrets.currentSecret);
    }
    
    if (secrets.previousSecrets) {
      secrets.previousSecrets.forEach(secret => {
        secretManager.addPreviousSecret(secret);
      });
    }

    this.initialized = true;
  }

  /**
   * Create password hash (async)
   */
  async createHash(password, options = {}) {
    this._ensureInitialized();
    this._validatePassword(password);

    const {
      algorithm = 'argon2id',
      pepper = null,
      salt = randomBytes(config.getConfig().saltLength),
      ...algorithmOptions
    } = options;

    // Create HMAC layer
    const hmacResult = hmac.createHMAC(password, salt, pepper);

    let derivedKey;
    let metadata = {
      version: config.getConfig().encoding.formatVersion,
      algorithm,
      salt
    };

    // Apply KDF layer
    if (algorithm === 'argon2id') {
      const { memoryCost, timeCost, parallelism } = config.getConfig().argon2;
      derivedKey = await argon2.deriveKey(hmacResult, salt, {
        memoryCost,
        timeCost,
        parallelism,
        ...algorithmOptions
      });
      Object.assign(metadata, { memoryCost, timeCost, parallelism });
    } else if (algorithm === 'pbkdf2') {
      const { iterations } = config.getConfig().pbkdf2;
      derivedKey = await pbkdf2.deriveKey(hmacResult, salt, {
        iterations,
        ...algorithmOptions
      });
      metadata.iterations = iterations;
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }

    metadata.hash = derivedKey;
    return encoder.encodeHash(metadata);
  }

  /**
   * Create password hash (sync)
   */
  createHashSync(password, options = {}) {
    this._ensureInitialized();
    this._validatePassword(password);

    const {
      algorithm = 'pbkdf2', // Default to PBKDF2 for sync
      pepper = null,
      salt = randomBytes(config.getConfig().saltLength),
      ...algorithmOptions
    } = options;

    if (algorithm === 'argon2id') {
      throw new Error('Argon2 is not available in sync mode');
    }

    const hmacResult = hmac.createHMAC(password, salt, pepper);
    let derivedKey;
    let metadata = {
      version: config.getConfig().encoding.formatVersion,
      algorithm,
      salt
    };

    if (algorithm === 'pbkdf2') {
      const { iterations } = config.getConfig().pbkdf2;
      derivedKey = pbkdf2.deriveKeySync(hmacResult, salt, {
        iterations,
        ...algorithmOptions
      });
      metadata.iterations = iterations;
    } else {
      throw new Error(`Unsupported sync algorithm: ${algorithm}`);
    }

    metadata.hash = derivedKey;
    return encoder.encodeHash(metadata);
  }

  /**
   * Verify password (async)
   */
  async verifyPassword(password, encodedHash, pepper = null) {
    return verifier.verifyPassword(password, encodedHash, pepper);
  }

  /**
   * Verify password (sync)
   */
  verifyPasswordSync(password, encodedHash, pepper = null) {
    return verifier.verifyPasswordSync(password, encodedHash, pepper);
  }

  /**
   * Extract metadata from hash
   */
  extractMetadata(encodedHash) {
    return encoder.extractMetadata(encodedHash);
  }

  /**
   * Migrate hash if outdated
   */
  async migrateHashIfOutdated(password, encodedHash, pepper = null) {
    return verifier.migrateHashIfOutdated(password, encodedHash, pepper);
  }

  /**
   * Generate cryptographically secure secret
   */
  generateSecret(length = 64) {
    return config.generateSecret(length);
  }

  /**
   * Generate cryptographically secure pepper
   */
  generatePepper(length = 32) {
    return hmac.generatePepper(length);
  }

  /**
   * Rotate master secret
   */
  rotateSecret(newSecret = null) {
    const secretToUse = newSecret || this.generateSecret();
    return secretManager.rotateSecrets(secretToUse);
  }

  /**
   * Security audit of hash
   */
  auditHash(encodedHash) {
    return verifier.auditHash(encodedHash);
  }

  /**
   * Ensure library is initialized
   */
  _ensureInitialized() {
    if (!this.initialized) {
      console.warn('HMAX-SECURE: Library not initialized. Call initialize() first.');
      // Auto-initialize with generated secret for convenience
      const tempSecret = this.generateSecret();
      secretManager.setCurrentSecret(tempSecret);
      this.initialized = true;
    }
  }

  /**
   * Validate password strength
   */
  _validatePassword(password) {
    if (typeof password !== 'string' && !(password instanceof Uint8Array)) {
      throw new Error('Password must be a string or Uint8Array');
    }

    if (password.length < 1) {
      throw new Error('Password cannot be empty');
    }

    if (password.length > 1024) {
      throw new Error('Password too long');
    }
  }

  /**
   * Get library version and info
   */
  getInfo() {
    return {
      name: 'hmax-secure',
      version: '1.0.0',
      securityLevel: 'enterprise-military',
      algorithms: encoder.getSupportedAlgorithms(),
      currentVersion: encoder.getCurrentVersion()
    };
  }
}

// Create singleton instance
const hmax = new HMaxSecure();

// Public API
export const {
  initialize,
  createHash,
  createHashSync,
  verifyPassword,
  verifyPasswordSync,
  extractMetadata,
  migrateHashIfOutdated,
  generateSecret,
  generatePepper,
  rotateSecret,
  auditHash,
  getInfo
} = hmax;

// Configuration API
export { default as config } from './config.js';
export { default as secretManager } from './secrets.js';

export default hmax;