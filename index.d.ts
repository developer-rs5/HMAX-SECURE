/**
 * HMAX-SECURE TypeScript Definitions
 * Complete type definitions for enterprise usage
 */

declare module 'hmax-secure' {
  // Core Types
  export interface HMaxConfig {
    saltLength: number;
    hmacAlgorithm: 'sha256' | 'sha384' | 'sha512';
    argon2: {
      memoryCost: number;
      timeCost: number;
      parallelism: number;
      version: number;
      associatedData: Buffer | null;
    };
    pbkdf2: {
      iterations: number;
      digest: 'sha256' | 'sha384' | 'sha512';
    };
    secrets: {
      enablePepper: boolean;
      enableRotation: boolean;
      maxPreviousSecrets: number;
      currentSecret: Buffer | null;
      previousSecrets: Buffer[];
    };
    encoding: {
      saltEncoding: 'base64' | 'hex';
      hashEncoding: 'base64' | 'hex';
      formatVersion: number;
    };
  }

  export interface HashMetadata {
    version: number;
    algorithm: 'argon2id' | 'pbkdf2' | 'hmac-sha512';
    salt: Buffer;
    hash: Buffer;
    iterations?: number;
    memoryCost?: number;
    timeCost?: number;
    parallelism?: number;
  }

  export interface PublicMetadata {
    version: number;
    algorithm: string;
    saltLength: number;
    hashLength: number;
    iterations?: number;
    memoryCost?: number;
    timeCost?: number;
    parallelism?: number;
  }

  export interface VerificationResult {
    verified: boolean;
    metadata?: PublicMetadata;
    needsMigration?: boolean;
    error?: string;
  }

  export interface MigrationResult {
    migrated: boolean;
    hash?: string;
    oldHash?: string;
    newHash?: string;
    reason?: string;
  }

  export interface AuditResult {
    secure: boolean;
    issues: string[];
    warnings: string[];
    metadata: PublicMetadata | null;
  }

  export interface HashOptions {
    algorithm?: 'argon2id' | 'pbkdf2';
    pepper?: Buffer | null;
    salt?: Buffer;
    iterations?: number;
    memoryCost?: number;
    timeCost?: number;
    parallelism?: number;
  }

  export interface SecretsConfig {
    currentSecret?: Buffer;
    previousSecrets?: Buffer[];
  }

  // Main API
  export function initialize(secrets?: SecretsConfig): Promise<void>;
  export function createHash(password: string | Uint8Array, options?: HashOptions): Promise<string>;
  export function createHashSync(password: string | Uint8Array, options?: HashOptions): string;
  export function verifyPassword(password: string | Uint8Array, encodedHash: string, pepper?: Buffer | null): Promise<VerificationResult>;
  export function verifyPasswordSync(password: string | Uint8Array, encodedHash: string, pepper?: Buffer | null): VerificationResult;
  export function extractMetadata(encodedHash: string): PublicMetadata;
  export function migrateHashIfOutdated(password: string | Uint8Array, encodedHash: string, pepper?: Buffer | null): Promise<MigrationResult>;
  export function generateSecret(length?: number): Buffer;
  export function generatePepper(length?: number): Buffer;
  export function rotateSecret(newSecret?: Buffer): string;
  export function auditHash(encodedHash: string): AuditResult;
  export function getInfo(): {
    name: string;
    version: string;
    securityLevel: string;
    algorithms: string[];
    currentVersion: number;
  };

  // Configuration API
  export const config: {
    getConfig(): HMaxConfig;
    setConfig(newConfig: Partial<HMaxConfig>): HMaxConfig;
    generateSecret(length?: number): Buffer;
  };

  // Secret Management API
  export const secretManager: {
    setCurrentSecret(secret: Buffer): string;
    addPreviousSecret(secret: Buffer, id?: string): string;
    rotateSecrets(newSecret: Buffer): string;
    getCurrentSecret(): Buffer;
    getAllSecrets(): Buffer[];
    onRotation(callback: (newSecretId: string, oldSecretId: string) => void): () => void;
    clear(): void;
  };

  export default {
    initialize,
    createHash,
    createHashSync,
    verifyPassword,
    verifyPasswordSync,
    extractMetadata,
    migrateHashIfOutdated,
    generateSecret,
    generatePepper,
    rotateSecret,
    auditHash,
    getInfo,
    config,
    secretManager
  };
}