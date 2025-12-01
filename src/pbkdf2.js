/**
 * HMAX-SECURE PBKDF2 Implementation
 * Fallback key derivation function
 */

import { pbkdf2, pbkdf2Sync, randomBytes } from "node:crypto";
import { promisify } from "node:util";
import config from "./config.js"; // MAKE SURE THIS PATH IS CORRECT

// Converted require → import
const pbkdf2Async = promisify(pbkdf2);

class PBKDF2KDF {
  /**
   * PBKDF2 key derivation (async)
   */
  async deriveKey(password, salt, options = {}) {
    const cfg = config.getConfig();
    const {
      iterations = cfg.pbkdf2.iterations,
      digest = cfg.pbkdf2.digest,
      keyLength = 64
    } = options;

    this._validateParams(iterations, digest, keyLength);

    return pbkdf2Async(password, salt, iterations, keyLength, digest);
  }

  /**
   * PBKDF2 key derivation (sync)
   */
  deriveKeySync(password, salt, options = {}) {
    const cfg = config.getConfig();
    const {
      iterations = cfg.pbkdf2.iterations,
      digest = cfg.pbkdf2.digest,
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
      throw new Error("Iterations must be between 10000 and 1000000");
    }

    if (!["sha256", "sha384", "sha512"].includes(digest)) {
      throw new Error("Invalid digest algorithm");
    }

    if (keyLength < 16 || keyLength > 128) {
      throw new Error("Key length must be between 16 and 128 bytes");
    }
  }

  /**
   * Calculate recommended iterations based on hardware
   */
  calculateOptimalIterations(targetMillis = 500) {
    const testPassword = "test_password";
    const testSalt = randomBytes(16);

    const start = Date.now();
    this.deriveKeySync(testPassword, testSalt, {
      iterations: 10000,
      keyLength: 64
    });
    const duration = Date.now() - start;

    const iterations = Math.floor(
      (targetMillis * 10000) / Math.max(duration, 1)
    );

    return Math.max(10000, Math.min(iterations, 1000000));
  }
}

export default new PBKDF2KDF();
