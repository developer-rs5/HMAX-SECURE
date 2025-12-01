/**
 * HMAX-SECURE Verification System
 * Comprehensive hash verification with rotation support
 */

import hmac from './hmac.js';
import argon2 from './argon2.js';
import pbkdf2 from './pbkdf2.js';
import timing from './timing.js';
import encoder from './encode.js';
import config from './config.js';
import secretManager from './secrets.js';

class HMaxVerifier {
  /**
   * Verify password against HMAX hash (async)
   */
  async verifyPassword(password, encodedHash, pepper = null) {
    try {
      // Decode the hash metadata
      const metadata = encoder.decodeHash(encodedHash);
      
      // Recompute the hash with the provided password
      const computedHash = await this._recomputeHash(password, metadata, pepper);
      
      // Timing-safe comparison
      const verified = timing.verifyHash(computedHash, metadata.hash);
      
      return {
        verified,
        metadata: encoder.extractMetadata(encodedHash),
        needsMigration: !verified ? false : encoder.needsMigration(encodedHash)
      };
    } catch (error) {
      return {
        verified: false,
        error: error.message,
        needsMigration: false
      };
    }
  }

  /**
   * Verify password (sync)
   */
  verifyPasswordSync(password, encodedHash, pepper = null) {
    try {
      const metadata = encoder.decodeHash(encodedHash);
      
      // Note: Argon2 should not be used in sync mode
      if (metadata.algorithm === 'argon2id') {
        throw new Error('Argon2 verification must be async');
      }
      
      const computedHash = this._recomputeHashSync(password, metadata, pepper);
      const verified = timing.verifyHash(computedHash, metadata.hash);
      
      return {
        verified,
        metadata: encoder.extractMetadata(encodedHash),
        needsMigration: !verified ? false : encoder.needsMigration(encodedHash)
      };
    } catch (error) {
      return {
        verified: false,
        error: error.message,
        needsMigration: false
      };
    }
  }

  /**
   * Recompute hash for verification (async)
   */
  async _recomputeHash(password, metadata, pepper = null) {
    const { algorithm, salt, version } = metadata;
    
    let derivedKey;
    
    // Apply HMAC layer first
    const hmacResult = hmac.createHMAC(password, salt, pepper);
    
    // Then apply KDF based on algorithm
    if (algorithm === 'argon2id') {
      const { timeCost, memoryCost, parallelism } = metadata;
      derivedKey = await argon2.deriveKey(hmacResult, salt, {
        timeCost,
        memoryCost,
        parallelism,
        keyLength: 64
      });
    } else if (algorithm === 'pbkdf2') {
      const { iterations } = metadata;
      derivedKey = await pbkdf2.deriveKey(hmacResult, salt, {
        iterations,
        keyLength: 64
      });
    } else if (algorithm === 'hmac-sha512') {
      // For v1 compatibility - just use HMAC result
      derivedKey = hmacResult;
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
    
    return derivedKey;
  }

  /**
   * Recompute hash for verification (sync)
   */
  _recomputeHashSync(password, metadata, pepper = null) {
    const { algorithm, salt } = metadata;
    
    const hmacResult = hmac.createHMAC(password, salt, pepper);
    
    if (algorithm === 'pbkdf2') {
      const { iterations } = metadata;
      return pbkdf2.deriveKeySync(hmacResult, salt, {
        iterations,
        keyLength: 64
      });
    } else if (algorithm === 'hmac-sha512') {
      return hmacResult;
    } else {
      throw new Error(`Unsupported sync algorithm: ${algorithm}`);
    }
  }

  /**
   * Migrate hash if outdated
   */
  async migrateHashIfOutdated(password, encodedHash, pepper = null) {
    const verification = await this.verifyPassword(password, encodedHash, pepper);
    
    if (!verification.verified) {
      throw new Error('Cannot migrate: password verification failed');
    }
    
    if (!verification.needsMigration) {
      return { migrated: false, hash: encodedHash };
    }
    
    // Re-hash with current parameters
    const { createHash } = await import('./index.js');
    const newHash = await createHash(password, { pepper });
    
    return {
      migrated: true,
      oldHash: encodedHash,
      newHash,
      reason: 'Hash parameters outdated'
    };
  }

  /**
   * Bulk verify passwords
   */
  async verifyMultiple(passwordsHashes, pepper = null) {
    const results = [];
    
    for (const { password, hash } of passwordsHashes) {
      const result = await this.verifyPassword(password, hash, pepper);
      results.push({
        verified: result.verified,
        needsMigration: result.needsMigration,
        error: result.error
      });
    }
    
    return results;
  }

  /**
   * Security audit of hash
   */
  auditHash(encodedHash) {
    try {
      const metadata = encoder.decodeHash(encodedHash);
      const currentConfig = config.getConfig();
      
      const issues = [];
      const warnings = [];
      
      // Check version
      if (metadata.version < currentConfig.encoding.formatVersion) {
        issues.push(`Outdated format version: ${metadata.version}`);
      }
      
      // Algorithm-specific checks
      if (metadata.algorithm === 'argon2id') {
        if (metadata.memoryCost < currentConfig.argon2.memoryCost) {
          issues.push(`Insufficient memory cost: ${metadata.memoryCost}`);
        }
        if (metadata.timeCost < currentConfig.argon2.timeCost) {
          issues.push(`Insufficient time cost: ${metadata.timeCost}`);
        }
      } else if (metadata.algorithm === 'pbkdf2') {
        if (metadata.iterations < currentConfig.pbkdf2.iterations) {
          issues.push(`Insufficient iterations: ${metadata.iterations}`);
        }
      } else if (metadata.algorithm === 'hmac-sha512') {
        warnings.push('Using legacy HMAC-only algorithm');
      }
      
      // General checks
      if (metadata.salt.length < 16) {
        issues.push('Salt too short');
      }
      
      if (metadata.hash.length < 32) {
        issues.push('Hash too short');
      }
      
      return {
        secure: issues.length === 0,
        issues,
        warnings,
        metadata: encoder.extractMetadata(encodedHash)
      };
    } catch (error) {
      return {
        secure: false,
        issues: [`Invalid hash format: ${error.message}`],
        warnings: [],
        metadata: null
      };
    }
  }
}

export default new HMaxVerifier();