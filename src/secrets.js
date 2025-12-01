/**
 * HMAX-SECURE Secret Management System
 * Military-grade secret rotation and management
 */

import config from './config.js';
import { timingSafeEqual } from './timing.js';

class SecretManager {
  constructor() {
    this.secrets = new Map();
    this.rotationCallbacks = new Set();
  }

  /**
   * Initialize secrets from configuration
   */
  initialize() {
    const { secrets } = config.getConfig();
    
    if (secrets.currentSecret) {
      this.setCurrentSecret(secrets.currentSecret);
    }
    
    secrets.previousSecrets.forEach((secret, index) => {
      this.addPreviousSecret(secret, index);
    });
  }

  /**
   * Set current primary secret
   */
  setCurrentSecret(secret) {
    if (!(secret instanceof Uint8Array)) {
      throw new Error('Secret must be a Uint8Array');
    }
    
    if (secret.length < 32) {
      throw new Error('Secret must be at least 32 bytes');
    }

    const secretId = this._generateSecretId();
    this.secrets.set('current', { id: secretId, secret, timestamp: Date.now() });
    
    return secretId;
  }

  /**
   * Add a previous secret for rotation
   */
  addPreviousSecret(secret, id = null) {
    if (!(secret instanceof Uint8Array)) {
      throw new Error('Secret must be a Uint8Array');
    }

    const secretId = id || this._generateSecretId();
    this.secrets.set(secretId, { id: secretId, secret, timestamp: Date.now() });
    
    return secretId;
  }

  /**
   * Rotate secrets - move current to previous, set new current
   */
  rotateSecrets(newSecret) {
    const current = this.secrets.get('current');
    if (!current) {
      throw new Error('No current secret set');
    }

    // Move current to previous
    this.secrets.delete('current');
    this.addPreviousSecret(current.secret, current.id);

    // Set new current
    const newId = this.setCurrentSecret(newSecret);

    // Trim old secrets if needed
    this._trimOldSecrets();

    // Notify rotation listeners
    this._notifyRotation(newId, current.id);

    return newId;
  }

  /**
   * Get current secret
   */
  getCurrentSecret() {
    const current = this.secrets.get('current');
    if (!current) {
      throw new Error('No current secret set');
    }
    return current.secret;
  }

  /**
   * Get all valid secrets (current + previous)
   */
  getAllSecrets() {
    const secrets = [];
    for (const [key, value] of this.secrets) {
      secrets.push(value.secret);
    }
    return secrets;
  }

  /**
   * Find which secret was used for a hash
   */
  findUsedSecret(hashBuffer, secretsToTry = null) {
    const secrets = secretsToTry || this.getAllSecrets();
    
    for (const secret of secrets) {
      // This is a simplified check - actual implementation would need
      // to reconstruct the hash with each secret
      try {
        // In practice, this would involve trying to verify with each secret
        // Implementation depends on how the secret is used in the hash
        if (this._testSecretWithHash(secret, hashBuffer)) {
          return secret;
        }
      } catch (error) {
        // Continue to next secret
        continue;
      }
    }
    
    return null;
  }

  /**
   * Test if a secret matches a hash (simplified)
   */
  _testSecretWithHash(secret, hashBuffer) {
    // This would be implemented based on the actual hash verification logic
    // For now, return a placeholder implementation
    return false;
  }

  /**
   * Generate a unique secret ID
   */
  _generateSecretId() {
    return `sec_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }

  /**
   * Trim old secrets based on configuration
   */
  _trimOldSecrets() {
    const { maxPreviousSecrets } = config.getConfig().secrets;
    const previousSecrets = Array.from(this.secrets.entries())
      .filter(([key]) => key !== 'current')
      .sort(([,a], [,b]) => b.timestamp - a.timestamp);

    // Remove excess secrets
    if (previousSecrets.length > maxPreviousSecrets) {
      for (let i = maxPreviousSecrets; i < previousSecrets.length; i++) {
        this.secrets.delete(previousSecrets[i][0]);
      }
    }
  }

  /**
   * Notify about secret rotation
   */
  _notifyRotation(newSecretId, oldSecretId) {
    for (const callback of this.rotationCallbacks) {
      try {
        callback(newSecretId, oldSecretId);
      } catch (error) {
        // Don't let one callback break others
        console.error('Secret rotation callback error:', error);
      }
    }
  }

  /**
   * Register for secret rotation events
   */
  onRotation(callback) {
    this.rotationCallbacks.add(callback);
    return () => this.rotationCallbacks.delete(callback);
  }

  /**
   * Clear all secrets (for testing/cleanup)
   */
  clear() {
    this.secrets.clear();
  }
}

export default new SecretManager();