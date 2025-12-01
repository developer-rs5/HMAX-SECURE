/**
 * HMAX-SECURE HMAC Core System
 * HMAC-SHA512 with dual-secret protection
 */

import { createHmac, randomBytes } from 'node:crypto';
import config from './config.js';
import secretManager from './secrets.js';

class HMACCore {
  /**
   * Create HMAC with master secret + pepper
   */
  createHMAC(data, salt, pepper = null) {
    const { hmacAlgorithm, secrets } = config.getConfig();
    
    const masterSecret = secretManager.getCurrentSecret();
    const usePepper = secrets.enablePepper && pepper;
    
    // Create layered HMAC: HMAC(masterSecret, HMAC(pepper, data || salt))
    let hmacData = data;
    
    // First layer: pepper if enabled
    if (usePepper) {
      const pepperHmac = createHmac(hmacAlgorithm, pepper);
      pepperHmac.update(salt);
      pepperHmac.update(data);
      hmacData = pepperHmac.digest();
    }
    
    // Second layer: master secret
    const masterHmac = createHmac(hmacAlgorithm, masterSecret);
    masterHmac.update(salt);
    masterHmac.update(hmacData);
    
    return masterHmac.digest();
  }

  /**
   * Verify HMAC with multiple secrets (rotation support)
   */
  verifyHMAC(data, salt, expectedHMAC, pepper = null) {
    const { hmacAlgorithm, secrets } = config.getConfig();
    const allSecrets = secretManager.getAllSecrets();
    
    // Try all secrets (current + previous) for rotation support
    for (const secret of allSecrets) {
      try {
        let hmacData = data;
        
        // First layer with pepper
        if (secrets.enablePepper && pepper) {
          const pepperHmac = createHmac(hmacAlgorithm, pepper);
          pepperHmac.update(salt);
          pepperHmac.update(data);
          hmacData = pepperHmac.digest();
        }
        
        // Second layer with current secret being tested
        const masterHmac = createHmac(hmacAlgorithm, secret);
        masterHmac.update(salt);
        masterHmac.update(hmacData);
        const computedHMAC = masterHmac.digest();
        
        // Use timing-safe comparison
        if (this.timingSafeEqual(computedHMAC, expectedHMAC)) {
          return {
            verified: true,
            usedCurrentSecret: secret === secretManager.getCurrentSecret()
          };
        }
      } catch (error) {
        // Continue to next secret
        continue;
      }
    }
    
    return { verified: false, usedCurrentSecret: false };
  }

  /**
   * Timing-safe buffer comparison
   */
  timingSafeEqual(a, b) {
    if (a.length !== b.length) {
      return false;
    }
    
    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a[i] ^ b[i];
    }
    return result === 0;
  }

  /**
   * Generate random pepper
   */
  generatePepper(length = 32) {
    if (length < 16 || length > 64) {
      throw new Error('Pepper length must be between 16 and 64 bytes');
    }
    return randomBytes(length);
  }

  /**
   * Create HMAC with specific secret (for testing/advanced use)
   */
  createHMACWithSecret(data, salt, secret, pepper = null) {
    const { hmacAlgorithm } = config.getConfig();
    
    let hmacData = data;
    
    if (pepper) {
      const pepperHmac = createHmac(hmacAlgorithm, pepper);
      pepperHmac.update(salt);
      pepperHmac.update(data);
      hmacData = pepperHmac.digest();
    }
    
    const masterHmac = createHmac(hmacAlgorithm, secret);
    masterHmac.update(salt);
    masterHmac.update(hmacData);
    
    return masterHmac.digest();
  }
}

export default new HMACCore();