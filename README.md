# HMAX-SECURE 🔒  
**Enterprise-Grade Military-Level Password Hashing System**

A comprehensive, bank-grade password hashing library implementing modern cryptographic best practices with HMAC, secret rotation, pepper support, and multiple KDF layers.

---

## 🚀 Features

- Multi-Layer Security: HMAC-SHA512 + Secret + Pepper + KDF (Argon2id/PBKDF2)  
- Secret Rotation: Automatic key rotation without password re-entry  
- Timing-Safe Verification  
- Versioned Output  
- NIST/FIPS compliant configurations  
- Zero Dependencies  
- TypeScript Ready  

---

## 📦 Installation

```bash
npm install hmax-secure
```

---

## 🛠 Quick Start

### Basic Usage

```javascript
import hmax from 'hmax-secure';

await hmax.initialize({
  currentSecret: hmax.generateSecret()
});

const hash = await hmax.createHash('mySecurePassword');
console.log(hash);

const result = await hmax.verifyPassword('mySecurePassword', hash);
console.log(result.verified);
```

---

## ⚙️ Advanced Configuration

```javascript
import hmax, { config } from 'hmax-secure';

config.setConfig({
  argon2: {
    memoryCost: 131072,
    timeCost: 4,
    parallelism: 2
  },
  secrets: {
    enablePepper: true,
    enableRotation: true,
    maxPreviousSecrets: 5
  }
});

await hmax.initialize({
  currentSecret: masterSecret,
  previousSecrets: [oldSecret1, oldSecret2]
});

const pepper = hmax.generatePepper();
const hash = await hmax.createHash('password', { pepper });
```

---

## 🔧 API Reference

### Core Methods

- `createHash(password, options?)`
- `verifyPassword(password, hash, pepper?)`
- `extractMetadata(hash)`
- `migrateHashIfOutdated(password, hash, pepper?)`
- `generateSecret(length?)`
- `generatePepper(length?)`
- `rotateSecret(newSecret?)`

### Config

- `config.getConfig()`
- `config.setConfig(newConfig)`

---

## 🛡 Security Features

### Multi-Layer Crypto Stack

- HMAC-SHA512 sealing  
- Per-password 32-byte random salt  
- Optional pepper  
- KDF layer (Argon2id or PBKDF2)  
- Timing-safe comparison  
- Versioned hash format  

---

## 🔄 Secret Rotation Example

```javascript
const newSecretId = hmax.rotateSecret();

const result = await hmax.verifyPassword('password', oldHash);

const migration = await hmax.migrateHashIfOutdated('password', oldHash);
if (migration.migrated) {
  // Save migration.newHash
}
```

---

## 🧬 Hash Format

```
hmax$<version>$<algorithm>$<salt>$<params>$<hash>
```

Examples:

```
hmax$2$argon2id$uTSYylWT...$3$65536$4$8A3B...
hmax$1$pbkdf2$kf8XylWT...$210000$kf8XylWT...
```

---

## 🔒 Security Recommendations

- Use 64+ byte master secrets  
- Store secrets away from hashes  
- Rotate every quarter  
- Peppers: 32+ bytes  
- Argon2id recommended  
- Aim for 500ms–1s compute time  

---

## 📋 Migration Strategy

```javascript
const legacyVerified = verifyWithLegacySystem(password, legacyHash);
if (legacyVerified) {
  const newHash = await hmax.createHash(password);
}
```

Check version:

```javascript
const metadata = hmax.extractMetadata(existingHash);
```

---

## 🖥 CLI Tool

```bash
npm install -g hmax-secure

hmax hash "myPassword"
hmax verify "myPassword" "hmax$2$argon2id$..."
hmax gen-secret
hmax gen-pepper
hmax inspect "hmax$2$argon2id$..."
```

---

## ⚠️ Security Warnings

- Never store secrets with hashes  
- Use secure RNG  
- Protect peppers  
- Apply proper key rotation  
- Always use HTTPS/TLS  

---

## 🏢 Enterprise Usage

### Banking

- HSM for secret storage  
- Quarterly key rotation  
- Dedicated peppers per microservice  

### Military/Government

- Multi-factor secret custody  
- Extreme Argon2 parameters  
- Regular penetration testing  

---

## 🔍 Testing & Auditing

```javascript
const audit = hmax.auditHash(storedHash);
console.log(audit.secure);
console.log(audit.issues);
```

---

## 📄 License  
MIT License

