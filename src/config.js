/**
 * HMAX-SECURE Configuration System
 * Bank-grade security configuration management
 */

import { randomBytes } from 'node:crypto';

// Default security configuration (NIST/FIPS compliant)
const DEFAULT_CONFIG = Object.freeze({
  // Core security parameters
  saltLength: 32, // 256-bit salt
  hmacAlgorithm: 'sha512',
  
  // Argon2id parameters (OWASP recommended)
  argon2: {
    memoryCost: 65536, // 64MB
    timeCost: 3,
    parallelism: 4,
    version: 0x13, // Argon2id v1.3
    associatedData: null
  },
  
  // PBKDF2 fallback parameters
  pbkdf2: {
    iterations: 210000, // OWASP 2023 recommendation
    digest: 'sha512'
  },
  
  // Secret management
  secrets: {
    enablePepper: true,
    enableRotation: true,
    maxPreviousSecrets: 3,
    currentSecret: null, // Must be set by application
    previousSecrets: []
  },
  
  // Output encoding
  encoding: {
    saltEncoding: 'base64',
    hashEncoding: 'base64',
    formatVersion: 2
  }
});

class HMaxConfig {
  constructor() {
    this._config = { ...DEFAULT_CONFIG };
    this._validators = this._setupValidators();
  }

  /**
   * Setup configuration validators
   */
  _setupValidators() {
    return {
      saltLength: (value) => value >= 16 && value <= 64,
      hmacAlgorithm: (value) => ['sha256', 'sha384', 'sha512'].includes(value),
      argon2: {
        memoryCost: (value) => value >= 4096 && value <= 1048576,
        timeCost: (value) => value >= 1 && value <= 10,
        parallelism: (value) => value >= 1 && value <= 16
      },
      pbkdf2: {
        iterations: (value) => value >= 10000 && value <= 1000000,
        digest: (value) => ['sha256', 'sha384', 'sha512'].includes(value)
      }
    };
  }

  /**
   * Get current configuration (immutable)
   */
  getConfig() {
    return Object.freeze(JSON.parse(JSON.stringify(this._config)));
  }

  /**
   * Update configuration with validation
   */
  setConfig(newConfig) {
    if (typeof newConfig !== 'object') {
      throw new Error('Configuration must be an object');
    }

    const mergedConfig = this._deepMerge(this._config, newConfig);
    
    // Validate the merged configuration
    this._validateConfig(mergedConfig);
    
    this._config = mergedConfig;
    return this.getConfig();
  }

  /**
   * Deep merge objects
   */
  _deepMerge(target, source) {
    const result = { ...target };
    
    for (const [key, value] of Object.entries(source)) {
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        result[key] = this._deepMerge(result[key] || {}, value);
      } else {
        result[key] = value;
      }
    }
    
    return result;
  }

  /**
   * Validate configuration parameters
   */
  _validateConfig(config) {
    // Validate salt length
    if (!this._validators.saltLength(config.saltLength)) {
      throw new Error('Salt length must be between 16 and 64 bytes');
    }

    // Validate HMAC algorithm
    if (!this._validators.hmacAlgorithm(config.hmacAlgorithm)) {
      throw new Error('Invalid HMAC algorithm');
    }

    // Validate Argon2 parameters
    const { argon2 } = config;
    if (!this._validators.argon2.memoryCost(argon2.memoryCost)) {
      throw new Error('Argon2 memoryCost must be between 4096 and 1048576');
    }
    if (!this._validators.argon2.timeCost(argon2.timeCost)) {
      throw new Error('Argon2 timeCost must be between 1 and 10');
    }
    if (!this._validators.argon2.parallelism(argon2.parallelism)) {
      throw new Error('Argon2 parallelism must be between 1 and 16');
    }

    // Validate PBKDF2 parameters
    const { pbkdf2 } = config;
    if (!this._validators.pbkdf2.iterations(pbkdf2.iterations)) {
      throw new Error('PBKDF2 iterations must be between 10000 and 1000000');
    }
    if (!this._validators.pbkdf2.digest(pbkdf2.digest)) {
      throw new Error('Invalid PBKDF2 digest algorithm');
    }

    // Validate secrets configuration
    if (config.secrets.enablePepper && !config.secrets.currentSecret) {
      throw new Error('Current secret must be set when pepper is enabled');
    }
  }

  /**
   * Generate a random secret for master key or pepper
   */
  generateSecret(length = 64) {
    if (length < 32 || length > 128) {
      throw new Error('Secret length must be between 32 and 128 bytes');
    }
    return randomBytes(length);
  }
}

export default new HMaxConfig();