/**
 * HMAX-SECURE Argon2 Implementation
 * Memory-hard key derivation function (preferred)
 */

import { randomBytes, scrypt } from 'node:crypto';
import { promisify } from 'node:util';

const scryptAsync = promisify(scrypt);

class Argon2KDF {
  /**
   * Argon2id-like implementation using Node.js crypto
   * Note: Native Argon2 would be preferred but Node.js doesn't have built-in support
   * This implements a similar memory-hard approach using scrypt
   */
  async deriveKey(password, salt, options = {}) {
    const config = config.getConfig();
    const {
      memoryCost = config.argon2.memoryCost,
      timeCost = config.argon2.timeCost,
      parallelism = config.argon2.parallelism,
      keyLength = 64
    } = options;

    // Validate parameters
    this._validateParams(memoryCost, timeCost, parallelism, keyLength);

    // Enhanced scrypt-based memory-hard KDF that approximates Argon2 properties
    return this._argon2idLikeDerivation(password, salt, {
      memoryCost,
      timeCost,
      parallelism,
      keyLength
    });
  }

  /**
   * Argon2id-like derivation using multiple scrypt passes
   */
  async _argon2idLikeDerivation(password, salt, options) {
    const { memoryCost, timeCost, parallelism, keyLength } = options;
    
    // Initial memory filling and compression phases
    let derivedKey = await this._memoryHardPhase(password, salt, memoryCost, parallelism);
    
    // Multiple passes for time hardness
    for (let i = 0; i < timeCost; i++) {
      derivedKey = await this._compressionPhase(derivedKey, salt, memoryCost, parallelism);
    }
    
    // Final key derivation
    return this._finalDerivation(derivedKey, salt, keyLength);
  }

  /**
   * Memory-hard phase
   */
  async _memoryHardPhase(password, salt, memoryCost, parallelism) {
    const blockSize = 1024; // 1KB blocks
    const totalBlocks = Math.floor(memoryCost / blockSize);
    
    // Create memory matrix
    const memory = [];
    
    // Fill memory with initial hashes
    for (let i = 0; i < totalBlocks; i++) {
      const blockSalt = Buffer.concat([salt, Buffer.from([i & 0xFF])]);
      const block = await scryptAsync(password, blockSalt, blockSize, {
        N: 16384,
        r: 8,
        p: 1,
        maxmem: 128 * 1024 * 1024
      });
      memory.push(block);
    }
    
    // Mix memory blocks
    return this._mixMemoryBlocks(memory, parallelism);
  }

  /**
   * Mix memory blocks with parallel processing simulation
   */
  async _mixMemoryBlocks(memory, parallelism) {
    const mixedBlocks = [];
    const segmentSize = Math.floor(memory.length / parallelism);
    
    for (let segment = 0; segment < parallelism; segment++) {
      const start = segment * segmentSize;
      const end = start + segmentSize;
      const segmentBlocks = memory.slice(start, end);
      
      // XOR all blocks in segment
      let mixedBlock = Buffer.alloc(segmentBlocks[0].length);
      for (const block of segmentBlocks) {
        for (let i = 0; i < mixedBlock.length; i++) {
          mixedBlock[i] ^= block[i];
        }
      }
      mixedBlocks.push(mixedBlock);
    }
    
    // Final mix of all segments
    let finalBlock = Buffer.alloc(mixedBlocks[0].length);
    for (const block of mixedBlocks) {
      for (let i = 0; i < finalBlock.length; i++) {
        finalBlock[i] ^= block[i];
      }
    }
    
    return finalBlock;
  }

  /**
   * Compression phase
   */
  async _compressionPhase(input, salt, memoryCost, parallelism) {
    // Additional memory-hard compression
    const compressed = await scryptAsync(input, salt, input.length, {
      N: memoryCost,
      r: 8,
      p: parallelism,
      maxmem: memoryCost * 3
    });
    
    return compressed;
  }

  /**
   * Final key derivation
   */
  async _finalDerivation(input, salt, keyLength) {
    return scryptAsync(input, salt, keyLength, {
      N: 16384,
      r: 8,
      p: 1,
      maxmem: 128 * 1024 * 1024
    });
  }

  /**
   * Validate Argon2 parameters
   */
  _validateParams(memoryCost, timeCost, parallelism, keyLength) {
    if (memoryCost < 4096 || memoryCost > 1048576) {
      throw new Error('Memory cost must be between 4096 and 1048576');
    }
    
    if (timeCost < 1 || timeCost > 10) {
      throw new Error('Time cost must be between 1 and 10');
    }
    
    if (parallelism < 1 || parallelism > 16) {
      throw new Error('Parallelism must be between 1 and 16');
    }
    
    if (keyLength < 16 || keyLength > 128) {
      throw new Error('Key length must be between 16 and 128 bytes');
    }
  }

  /**
   * Sync version (not recommended for production)
   */
  deriveKeySync(password, salt, options = {}) {
    // For compatibility, but async is strongly recommended
    throw new Error('Argon2 derivation should be async. Use deriveKey instead.');
  }
}

export default new Argon2KDF();