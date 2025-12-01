/**
 * HMAX-SECURE Timing-Safe Utilities
 * Prevent timing attacks on verification
 */

import { timingSafeEqual } from 'node:crypto';

class TimingSafe {
  /**
   * Constant-time buffer comparison
   */
  bufferEqual(a, b) {
    if (!(a instanceof Buffer) || !(b instanceof Buffer)) {
      throw new Error('Both arguments must be buffers');
    }
    
    return timingSafeEqual(a, b);
  }

  /**
   * Constant-time string comparison
   */
  stringEqual(a, b) {
    const encoder = new TextEncoder();
    const aBuf = encoder.encode(a);
    const bBuf = encoder.encode(b);
    
    return this.bufferEqual(aBuf, bBuf);
  }

  /**
   * Constant-time hash verification
   */
  verifyHash(provided, expected) {
    if (provided.length !== expected.length) {
      // Use constant-time comparison even for length mismatch
      const dummy = Buffer.alloc(expected.length);
      return timingSafeEqual(dummy, dummy) && false;
    }
    
    return timingSafeEqual(provided, expected);
  }

  /**
   * Constant-time array comparison
   */
  arrayEqual(a, b) {
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
   * Secure cleanup of sensitive data
   */
  secureClean(buffer) {
    if (buffer && buffer.fill) {
      buffer.fill(0);
    }
  }

  /**
   * Constant-time select (avoid branch prediction)
   */
  select(condition, trueValue, falseValue) {
    const mask = condition ? 0xFF : 0x00;
    const result = new Uint8Array(trueValue.length);
    
    for (let i = 0; i < trueValue.length; i++) {
      result[i] = (trueValue[i] & mask) | (falseValue[i] & ~mask);
    }
    
    return result;
  }
}

export default new TimingSafe();