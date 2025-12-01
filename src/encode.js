/**
 * HMAX-SECURE Output Encoding System
 * Versioned, extensible hash format
 */

import config from './config.js';

class HMaxEncoder {
  /**
   * Encode hash to HMAX format string
   */
  encodeHash(metadata) {
    const {
      version = 2,
      algorithm = 'argon2id',
      salt,
      iterations,
      hash,
      memoryCost,
      parallelism,
      timeCost
    } = metadata;

    this._validateMetadata(metadata);

    const parts = [
      'hmax',
      version.toString(),
      algorithm,
      this._encodeComponent(salt)
    ];

    // Add algorithm-specific parameters
    if (algorithm === 'argon2id') {
      parts.push(timeCost.toString());
      parts.push(memoryCost.toString());
      parts.push(parallelism.toString());
    } else if (algorithm === 'pbkdf2' || algorithm === 'hmac-sha512') {
      parts.push(iterations.toString());
    }

    parts.push(this._encodeComponent(hash));

    return parts.join('$');
  }

  /**
   * Decode HMAX format string to metadata
   */
  decodeHash(encodedString) {
    if (typeof encodedString !== 'string') {
      throw new Error('Encoded string must be a string');
    }

    const parts = encodedString.split('$');
    
    if (parts.length < 6) {
      throw new Error('Invalid HMAX format: insufficient parts');
    }

    if (parts[0] !== 'hmax') {
      throw new Error('Invalid HMAX format: missing hmax prefix');
    }

    const version = parseInt(parts[1], 10);
    const algorithm = parts[2];
    const salt = this._decodeComponent(parts[3]);

    let metadata = {
      version,
      algorithm,
      salt
    };

    // Parse algorithm-specific parameters
    if (algorithm === 'argon2id') {
      if (parts.length !== 8) {
        throw new Error('Invalid Argon2id format');
      }
      metadata.timeCost = parseInt(parts[4], 10);
      metadata.memoryCost = parseInt(parts[5], 10);
      metadata.parallelism = parseInt(parts[6], 10);
      metadata.hash = this._decodeComponent(parts[7]);
    } else if (algorithm === 'pbkdf2' || algorithm === 'hmac-sha512') {
      if (parts.length !== 6) {
        throw new Error('Invalid PBKDF2/HMAC format');
      }
      metadata.iterations = parseInt(parts[4], 10);
      metadata.hash = this._decodeComponent(parts[5]);
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }

    return metadata;
  }

  /**
   * Extract metadata without verification
   */
  extractMetadata(encodedString) {
    try {
      const metadata = this.decodeHash(encodedString);
      
      // Remove sensitive data from metadata
      const { hash, salt, ...publicMetadata } = metadata;
      
      return {
        ...publicMetadata,
        hashLength: hash?.length,
        saltLength: salt?.length
      };
    } catch (error) {
      throw new Error(`Failed to extract metadata: ${error.message}`);
    }
  }

  /**
   * Check if hash needs migration
   */
  needsMigration(encodedString, currentConfig = null) {
    const config = currentConfig || config.getConfig();
    const metadata = this.decodeHash(encodedString);

    // Check version
    if (metadata.version < config.encoding.formatVersion) {
      return true;
    }

    // Check algorithm-specific parameters
    if (metadata.algorithm === 'argon2id') {
      const { argon2 } = config;
      return (
        metadata.timeCost < argon2.timeCost ||
        metadata.memoryCost < argon2.memoryCost ||
        metadata.parallelism < argon2.parallelism
      );
    } else if (metadata.algorithm === 'pbkdf2') {
      const { pbkdf2 } = config;
      return metadata.iterations < pbkdf2.iterations;
    }

    return false;
  }

  /**
   * Encode component (salt/hash) to string
   */
  _encodeComponent(buffer) {
    if (!(buffer instanceof Uint8Array) && !Buffer.isBuffer(buffer)) {
      throw new Error('Component must be a Buffer or Uint8Array');
    }
    return Buffer.from(buffer).toString('base64');
  }

  /**
   * Decode component from string
   */
  _decodeComponent(encoded) {
    return Buffer.from(encoded, 'base64');
  }

  /**
   * Validate metadata before encoding
   */
  _validateMetadata(metadata) {
    const { version, algorithm, salt, hash } = metadata;

    if (version < 1 || version > 999) {
      throw new Error('Version must be between 1 and 999');
    }

    if (!['argon2id', 'pbkdf2', 'hmac-sha512'].includes(algorithm)) {
      throw new Error('Unsupported algorithm');
    }

    if (!salt || salt.length < 16) {
      throw new Error('Salt must be at least 16 bytes');
    }

    if (!hash || hash.length < 32) {
      throw new Error('Hash must be at least 32 bytes');
    }

    // Algorithm-specific validation
    if (algorithm === 'argon2id') {
      const { timeCost, memoryCost, parallelism } = metadata;
      if (timeCost < 1 || timeCost > 10) throw new Error('Invalid timeCost');
      if (memoryCost < 4096 || memoryCost > 1048576) throw new Error('Invalid memoryCost');
      if (parallelism < 1 || parallelism > 16) throw new Error('Invalid parallelism');
    } else if (algorithm === 'pbkdf2' || algorithm === 'hmac-sha512') {
      const { iterations } = metadata;
      if (iterations < 1000 || iterations > 1000000) throw new Error('Invalid iterations');
    }
  }

  /**
   * Get supported algorithms
   */
  getSupportedAlgorithms() {
    return ['argon2id', 'pbkdf2', 'hmac-sha512'];
  }

  /**
   * Get current format version
   */
  getCurrentVersion() {
    return config.getConfig().encoding.formatVersion;
  }
}

export default new HMaxEncoder();