/**
 * HMAX-SECURE PBKDF2 Implementation
 * Fallback key derivation function
 */

import { pbkdf2Sync, randomBytes } from 'node:crypto';
import { promisify } from 'node:util';

const pbkdf2Async = promisify(require('node:crypto').pbkdf2);

class PBKDF2KDF {
  /**
   * PBKDF2 key derivation (async)
   */
  async deriveKey(password, salt, options = {}) {
    const config = config.getConfig();
    const {
      iterations = config.pbkdf2.iterations,
      digest = config.pbkdf2.digest,
      keyLength = 64
    } = options;

    this._validateParams(iterations, digest, keyLength);

    return pbkdf2Async(password, salt, iterations, keyLength, digest);
  }

  /**
   * PBKDF2 key derivation (sync)
   */
  deriveKeySync(password, salt, options = {}) {
    const config = config.getConfig();
    const {
      iterations = config.pbkdf2.iterations,
      digest = config.pbkdf2.digest,
      keyLength = 64
    } = options;

    this._validateParams(iterations, digest, keyLength);

    return pbkdf2Sync(password, salt, iterations, keyLength, digest);
  }

  /**
   * Validate PBKDF2 parameters
   */
  _validateParams(iterations, digest, keyLength) {
    if (iterations < 10000 || iterations > 1000000) {
      throw new Error('Iterations must be between 10000 and 1000000');
    }
    
    if (!['sha256', 'sha384', 'sha512'].includes(digest)) {
      throw new Error('Invalid digest algorithm');
    }
    
    if (keyLength < 16 || keyLength > 128) {
      throw new Error('Key length must be between 16 and 128 bytes');
    }
  }

  /**
   * Calculate recommended iterations based on hardware
   */
  calculateOptimalIterations(targetMillis = 500) {
    // Simple benchmark to calculate iterations for target duration
    const testPassword = 'test_password';
    const testSalt = randomBytes(16);
    const start = Date.now();
    
    // Run quick benchmark
    this.deriveKeySync(testPassword, testSalt, { iterations: 10000, keyLength: 64 });
    const duration = Date.now() - start;
    
    // Calculate iterations for target duration
    const iterations = Math.floor((targetMillis * 10000) / Math.max(duration, 1));
    
    // Ensure within safe bounds
    return Math.max(10000, Math.min(iterations, 1000000));
  }
}

export default new PBKDF2KDF();