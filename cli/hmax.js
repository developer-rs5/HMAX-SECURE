#!/usr/bin/env node

/**
 * HMAX-SECURE CLI Tool
 * Global binary for password hashing operations
 */

import { readFileSync } from 'node:fs';
import { argv, exit } from 'node:process';
import hmax, { config, generateSecret, generatePepper } from '../src/index.js';

// CLI version
const CLI_VERSION = '1.0.0';

// Help text
const HELP_TEXT = `
HMAX-SECURE CLI v${CLI_VERSION}
Enterprise-grade password hashing system

Usage:
  hmax <command> [options]

Commands:
  hash <password>          Hash a password
  verify <password> <hash> Verify a password against a hash
  gen-secret              Generate a new master secret
  gen-pepper              Generate a new pepper
  inspect <hash>          Inspect hash metadata and security
  config                  Show current configuration

Options:
  --algorithm <alg>       Hash algorithm (argon2id, pbkdf2)
  --pepper <file>         Pepper file path
  --config <file>         Configuration file
  --help                 Show this help
  --version              Show version

Examples:
  hmax hash "myPassword"
  hmax verify "myPassword" "hmax$2$argon2id$..."
  hmax gen-secret
  hmax inspect "hmax$2$argon2id$..."
`;

/**
 * Main CLI handler
 */
async function main() {
  const args = argv.slice(2);
  
  if (args.length === 0 || args.includes('--help')) {
    console.log(HELP_TEXT);
    return;
  }

  if (args.includes('--version')) {
    console.log(`HMAX-SECURE CLI v${CLI_VERSION}`);
    return;
  }

  const command = args[0];

  try {
    await hmax.initialize();

    switch (command) {
      case 'hash':
        await handleHash(args.slice(1));
        break;
      case 'verify':
        await handleVerify(args.slice(1));
        break;
      case 'gen-secret':
        handleGenSecret();
        break;
      case 'gen-pepper':
        handleGenPepper();
        break;
      case 'inspect':
        handleInspect(args.slice(1));
        break;
      case 'config':
        handleConfig();
        break;
      default:
        console.error(`Unknown command: ${command}`);
        console.log(HELP_TEXT);
        exit(1);
    }
  } catch (error) {
    console.error(`Error: ${error.message}`);
    exit(1);
  }
}

/**
 * Handle hash command
 */
async function handleHash(args) {
  const password = args[0];
  if (!password) {
    throw new Error('Password required for hash command');
  }

  const options = parseOptions(args.slice(1));
  const pepper = await loadPepper(options.pepper);

  const hash = await hmax.createHash(password, { pepper });
  console.log(hash);
}

/**
 * Handle verify command
 */
async function handleVerify(args) {
  const password = args[0];
  const hash = args[1];

  if (!password || !hash) {
    throw new Error('Password and hash required for verify command');
  }

  const options = parseOptions(args.slice(2));
  const pepper = await loadPepper(options.pepper);

  const result = await hmax.verifyPassword(password, hash, pepper);
  
  if (result.verified) {
    console.log('✓ Password verified successfully');
    if (result.needsMigration) {
      console.log('⚠ Hash should be migrated to current security parameters');
    }
  } else {
    console.log('✗ Password verification failed');
    if (result.error) {
      console.log(`Error: ${result.error}`);
    }
    exit(1);
  }
}

/**
 * Handle generate secret command
 */
function handleGenSecret() {
  const secret = generateSecret();
  console.log('Master Secret (base64):');
  console.log(secret.toString('base64'));
  console.log('\nMaster Secret (hex):');
  console.log(secret.toString('hex'));
}

/**
 * Handle generate pepper command
 */
function handleGenPepper() {
  const pepper = generatePepper();
  console.log('Pepper (base64):');
  console.log(pepper.toString('base64'));
  console.log('\nPepper (hex):');
  console.log(pepper.toString('hex'));
}

/**
 * Handle inspect command
 */
function handleInspect(args) {
  const hash = args[0];
  if (!hash) {
    throw new Error('Hash required for inspect command');
  }

  const metadata = hmax.extractMetadata(hash);
  const audit = hmax.auditHash(hash);

  console.log('Hash Inspection Report:');
  console.log('======================');
  console.log(`Format: ${metadata.algorithm} v${metadata.version}`);
  console.log(`Security: ${audit.secure ? '✓ SECURE' : '✗ INSECURE'}`);
  
  if (audit.issues.length > 0) {
    console.log('\nSecurity Issues:');
    audit.issues.forEach(issue => console.log(`  ✗ ${issue}`));
  }
  
  if (audit.warnings.length > 0) {
    console.log('\nWarnings:');
    audit.warnings.forEach(warning => console.log(`  ⚠ ${warning}`));
  }

  console.log('\nMetadata:');
  console.log(`  Algorithm: ${metadata.algorithm}`);
  console.log(`  Version: ${metadata.version}`);
  console.log(`  Salt Length: ${metadata.saltLength} bytes`);
  console.log(`  Hash Length: ${metadata.hashLength} bytes`);

  if (metadata.algorithm === 'argon2id') {
    console.log(`  Memory Cost: ${metadata.memoryCost}`);
    console.log(`  Time Cost: ${metadata.timeCost}`);
    console.log(`  Parallelism: ${metadata.parallelism}`);
  } else if (metadata.algorithm === 'pbkdf2') {
    console.log(`  Iterations: ${metadata.iterations}`);
  }
}

/**
 * Handle config command
 */
function handleConfig() {
  const currentConfig = config.getConfig();
  console.log('Current Configuration:');
  console.log(JSON.stringify(currentConfig, null, 2));
}

/**
 * Parse CLI options
 */
function parseOptions(args) {
  const options = {};
  
  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--algorithm' && args[i + 1]) {
      options.algorithm = args[++i];
    } else if (args[i] === '--pepper' && args[i + 1]) {
      options.pepper = args[++i];
    } else if (args[i] === '--config' && args[i + 1]) {
      // Load configuration file
      const configFile = args[++i];
      const configData = JSON.parse(readFileSync(configFile, 'utf8'));
      config.setConfig(configData);
    }
  }
  
  return options;
}

/**
 * Load pepper from file
 */
async function loadPepper(pepperFile) {
  if (!pepperFile) return null;
  
  try {
    const pepperData = readFileSync(pepperFile, 'utf8').trim();
    
    // Try to parse as base64 first, then hex
    try {
      return Buffer.from(pepperData, 'base64');
    } catch {
      return Buffer.from(pepperData, 'hex');
    }
  } catch (error) {
    throw new Error(`Failed to load pepper from ${pepperFile}: ${error.message}`);
  }
}

// Run CLI
main().catch(error => {
  console.error(`Fatal error: ${error.message}`);
  exit(1);
});