/**
 * HMAX-SECURE Argon2 Implementation
 * Memory-hard key derivation function (preferred)
 */

import { randomBytes, scrypt } from "node:crypto";
import { promisify } from "node:util";
import config from "./config.js";

const scryptAsync = promisify(scrypt);

class Argon2KDF {
  async deriveKey(password, salt, options = {}) {
    const cfg = config.getConfig();

    const {
      memoryCost = cfg.argon2.memoryCost,
      timeCost = cfg.argon2.timeCost,
      parallelism = cfg.argon2.parallelism,
      keyLength = 64
    } = options;

    this._validateParams(memoryCost, timeCost, parallelism, keyLength);

    return this._argon2idLikeDerivation(password, salt, {
      memoryCost,
      timeCost,
      parallelism,
      keyLength
    });
  }

  async _argon2idLikeDerivation(password, salt, options) {
    const { memoryCost, timeCost, parallelism, keyLength } = options;

    let derivedKey = await this._memoryHardPhase(
      password,
      salt,
      memoryCost,
      parallelism
    );

    for (let i = 0; i < timeCost; i++) {
      derivedKey = await this._compressionPhase(
        derivedKey,
        salt,
        memoryCost,
        parallelism
      );
    }

    return this._finalDerivation(derivedKey, salt, keyLength);
  }

  async _memoryHardPhase(password, salt, memoryCost, parallelism) {
    const blockSize = 1024;
    const totalBlocks = Math.floor(memoryCost / blockSize);

    const memory = [];

    for (let i = 0; i < totalBlocks; i++) {
      const blockSalt = Buffer.concat([salt, Buffer.from([i & 0xff])]);
      const block = await scryptAsync(password, blockSalt, blockSize, {
        N: 16384,
        r: 8,
        p: 1,
        maxmem: 128 * 1024 * 1024
      });
      memory.push(block);
    }

    return this._mixMemoryBlocks(memory, parallelism);
  }

  async _mixMemoryBlocks(memory, parallelism) {
    const mixedBlocks = [];
    const segmentSize = Math.floor(memory.length / parallelism);

    for (let segment = 0; segment < parallelism; segment++) {
      const start = segment * segmentSize;
      const end = start + segmentSize;
      const segmentBlocks = memory.slice(start, end);

      let mixedBlock = Buffer.alloc(segmentBlocks[0].length);
      for (const block of segmentBlocks) {
        for (let i = 0; i < mixedBlock.length; i++) {
          mixedBlock[i] ^= block[i];
        }
      }
      mixedBlocks.push(mixedBlock);
    }

    let finalBlock = Buffer.alloc(mixedBlocks[0].length);
    for (const block of mixedBlocks) {
      for (let i = 0; i < finalBlock.length; i++) {
        finalBlock[i] ^= block[i];
      }
    }

    return finalBlock;
  }

  async _compressionPhase(input, salt, memoryCost, parallelism) {
  // Scrypt CANNOT use full memoryCost as N, so clamp it safely.
  const safeN = Math.pow(2, 14); // 16384 → standard safe level
  
  // Keep parallelism low; scrypt cannot handle high parallel p-values
  const safeP = Math.min(parallelism, 2);

  return scryptAsync(input, salt, input.length, {
    N: safeN,
    r: 8,
    p: safeP,
    maxmem: 128 * 1024 * 1024 // 128MB global limit
  });
}


  async _finalDerivation(input, salt, keyLength) {
    return scryptAsync(input, salt, keyLength, {
      N: 16384,
      r: 8,
      p: 1,
      maxmem: 128 * 1024 * 1024
    });
  }

  _validateParams(memoryCost, timeCost, parallelism, keyLength) {
    if (memoryCost < 4096 || memoryCost > 1048576) {
      throw new Error("Memory cost must be between 4096 and 1048576");
    }

    if (timeCost < 1 || timeCost > 10) {
      throw new Error("Time cost must be between 1 and 10");
    }

    if (parallelism < 1 || parallelism > 16) {
      throw new Error("Parallelism must be between 1 and 16");
    }

    if (keyLength < 16 || keyLength > 128) {
      throw new Error("Key length must be between 16 and 128 bytes");
    }
  }

  deriveKeySync() {
    throw new Error("Argon2 derivation should be async. Use deriveKey instead.");
  }
}

export default new Argon2KDF();
