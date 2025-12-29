# aegis-aead

[![npm](https://img.shields.io/npm/v/aegis-aead)](https://www.npmjs.com/package/aegis-aead)
[![CI](https://github.com/jedisct1/js-aegis-aead/actions/workflows/ci.yml/badge.svg)](https://github.com/jedisct1/js-aegis-aead/actions/workflows/ci.yml)

[View on npm](https://www.npmjs.com/package/aegis-aead)

A compact, zero-dependency JavaScript/TypeScript implementation of [AEGIS](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/), a family of fast, secure authenticated encryption algorithms.

AEGIS provides both encryption with authentication and standalone MAC functionality, with a simple API that makes it hard to misuse.

## Table of Contents

- [aegis-aead](#aegis-aead)
  - [Table of Contents](#table-of-contents)
  - [Installation](#installation)
  - [Quick Start](#quick-start)
  - [Choosing an Algorithm](#choosing-an-algorithm)
  - [Usage Examples](#usage-examples)
    - [Combined Mode](#combined-mode)
    - [Detached Mode](#detached-mode)
    - [In-Place Mode](#in-place-mode)
    - [MAC (Message Authentication Code)](#mac-message-authentication-code)
  - [API Overview](#api-overview)
    - [Functions](#functions)
    - [Parameters](#parameters)
    - [Constants](#constants)
    - [Parallel Variants (AEGIS-128X / AEGIS-256X)](#parallel-variants-aegis-128x--aegis-256x)
  - [Security Considerations](#security-considerations)
    - [Nonce Safety](#nonce-safety)
    - [Tag Lengths](#tag-lengths)
    - [Bitsliced Variants](#bitsliced-variants)
  - [Compatibility](#compatibility)
  - [Browser Example](#browser-example)

## Installation

```bash
bun add aegis-aead
# or
npm install aegis-aead
```

## Quick Start

```typescript
import { aegis128LCreateKey, aegis128LEncrypt, aegis128LDecrypt } from "aegis-aead";

const key = aegis128LCreateKey();
const message = new TextEncoder().encode("Hello, world!");
const associatedData = new TextEncoder().encode("metadata");

// Encrypt (nonce is generated automatically)
const sealed = aegis128LEncrypt(message, associatedData, key);

// Decrypt (returns null if authentication fails)
const decrypted = aegis128LDecrypt(sealed, associatedData, key);
```

## Choosing an Algorithm

| Algorithm     | Key      | Nonce    | Best For                                 |
| ------------- | -------- | -------- | ---------------------------------------- |
| AEGIS-128L    | 16 bytes | 16 bytes | General use, high throughput             |
| AEGIS-256     | 32 bytes | 32 bytes | Large nonce, unlimited messages          |
| AEGIS-128X    | 16 bytes | 16 bytes | Interop with native SIMD implementations |
| AEGIS-256X    | 32 bytes | 32 bytes | Interop + large nonce                    |
| AEGIS-128L-BS | 16 bytes | 16 bytes | Side-channel protection                  |
| AEGIS-256-BS  | 32 bytes | 32 bytes | Side-channel + large nonce               |

Recommendations:

- Default choice: AEGIS-128L offers excellent performance with safe random nonces up to 2^48 messages
- Unlimited messages: AEGIS-256 when you need unlimited random nonces (32-byte nonce eliminates collision risk)
- Interoperability: AEGIS-128X/256X when exchanging data with native implementations using these variants
- Hostile environments: Bitsliced variants (-BS) when attackers may observe timing

Note: The X variants are designed for SIMD parallelism in native code. In JavaScript they offer no speed benefit but are provided for interoperability.

## Usage Examples

### Combined Mode

The simplest API: returns `nonce || ciphertext || tag` in one buffer.

```typescript
import { aegis128LCreateKey, aegis128LEncrypt, aegis128LDecrypt } from "aegis-aead";

const key = aegis128LCreateKey();
const message = new TextEncoder().encode("Hello, world!");
const ad = new TextEncoder().encode("metadata");

const sealed = aegis128LEncrypt(message, ad, key);
const decrypted = aegis128LDecrypt(sealed, ad, key);
```

### Detached Mode

When you need separate access to ciphertext and tag:

```typescript
import {
  aegis128LCreateKey,
  aegis128LCreateNonce,
  aegis128LEncryptDetached,
  aegis128LDecryptDetached
} from "aegis-aead";

const key = aegis128LCreateKey();
const nonce = aegis128LCreateNonce();
const message = new TextEncoder().encode("Hello, world!");
const ad = new TextEncoder().encode("metadata");

const { ciphertext, tag } = aegis128LEncryptDetached(message, ad, key, nonce);
const decrypted = aegis128LDecryptDetached(ciphertext, tag, ad, key, nonce);
```

### In-Place Mode

Zero-copy encryption that modifies the buffer directly:

```typescript
import {
  aegis128LCreateKey,
  aegis128LCreateNonce,
  aegis128LEncryptDetachedInPlace,
  aegis128LDecryptDetachedInPlace
} from "aegis-aead";

const key = aegis128LCreateKey();
const nonce = aegis128LCreateNonce();
const data = new TextEncoder().encode("Hello, world!");
const ad = new TextEncoder().encode("metadata");

// Encrypt: data is modified, tag is returned
const tag = aegis128LEncryptDetachedInPlace(data, ad, key, nonce);

// Decrypt: returns true if authentication succeeds
const success = aegis128LDecryptDetachedInPlace(data, tag, ad, key, nonce);
```

### MAC (Message Authentication Code)

Authenticate data without encrypting:

```typescript
import { aegis128LCreateKey, aegis128LMac, aegis128LMacVerify } from "aegis-aead";

const key = aegis128LCreateKey();
const data = new TextEncoder().encode("data to authenticate");

const tag = aegis128LMac(data, key);
const valid = aegis128LMacVerify(data, tag, key);
```

## API Overview

All AEGIS variants follow the same API pattern. Replace `aegis128L` with your chosen algorithm (`aegis256`, `aegis128X2`, `aegis128X4`, `aegis256X2`, `aegis256X4`, `aegis128LBs`, `aegis256Bs`).

### Functions

| Function                                                | Description                                        |
| ------------------------------------------------------- | -------------------------------------------------- |
| `createKey()`                                           | Generate a random key                              |
| `createNonce()`                                         | Generate a random nonce                            |
| `encrypt(msg, ad, key, nonce?, tagLen?)`                | Encrypt, returns `nonce \|\| ciphertext \|\| tag`  |
| `decrypt(sealed, ad, key, tagLen?)`                     | Decrypt combined output, returns `null` on failure |
| `encryptDetached(msg, ad, key, nonce, tagLen?)`         | Encrypt, returns `{ ciphertext, tag }`             |
| `decryptDetached(ct, tag, ad, key, nonce)`              | Decrypt detached, returns `null` on failure        |
| `encryptDetachedInPlace(data, ad, key, nonce, tagLen?)` | Encrypt in-place, returns tag                      |
| `decryptDetachedInPlace(data, tag, ad, key, nonce)`     | Decrypt in-place, returns `boolean`                |
| `mac(data, key, nonce?, tagLen?)`                       | Generate MAC tag                                   |
| `macVerify(data, tag, key, nonce?)`                     | Verify MAC tag                                     |

### Parameters

- msg/data: `Uint8Array` - Data to encrypt/authenticate
- ad: `Uint8Array` - Associated data (authenticated but not encrypted)
- key: `Uint8Array` - Encryption key (16 or 32 bytes depending on algorithm)
- nonce: `Uint8Array` - Number used once (auto-generated if omitted in combined mode)
- tagLen: `number` - Authentication tag length: `16` (default) or `32`

### Constants

Each algorithm exports size constants:

```typescript
import { AEGIS_128L_KEY_SIZE, AEGIS_128L_NONCE_SIZE } from "aegis-aead";
// AEGIS_128L_KEY_SIZE = 16
// AEGIS_128L_NONCE_SIZE = 16
```

### Parallel Variants (AEGIS-128X / AEGIS-256X)

The X variants support a configurable degree of parallelism:

```typescript
// Pre-configured for degree 2 and 4
import { aegis128X2Encrypt, aegis128X4Encrypt } from "aegis-aead";

// Or use custom degree (typically 2 or 4)
import { aegis128XEncrypt } from "aegis-aead";
const sealed = aegis128XEncrypt(msg, ad, key, nonce, 16, 4); // degree=4
```

## Security Considerations

### Nonce Safety

- Combined mode generates random nonces automatically
- Detached mode requires you to provide nonces - never reuse a nonce with the same key
- AEGIS-128L/128X: Safe for up to 2^48 messages per key with random nonces
- AEGIS-256/256X: No practical limits on message count

### Tag Lengths

All algorithms support 16-byte (128-bit) and 32-byte (256-bit) tags:

```typescript
// 32-byte tag
const sealed = aegis128LEncrypt(msg, ad, key, undefined, 32);
```

### Bitsliced Variants

The `-BS` variants use a constant-time bitsliced AES implementation that doesn't use lookup tables. This prevents cache-timing attacks at the cost of ~20% performance.

Use bitsliced variants when:
- Running on shared infrastructure (cloud VMs, containers)
- Attackers may observe timing information
- Processing attacker-controlled data with secret keys

For most applications, standard variants are safe since AEGIS's continuous state mixing makes timing attacks impractical.

## Compatibility

Runtime Requirements:

The library uses the Web Crypto API (`crypto.getRandomValues`) for key/nonce generation:

- All modern browsers
- Node.js 18+
- Deno
- Bun

Interoperability:

This library implements the [AEGIS IETF draft specification](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/) and interoperates with any compliant implementation. See the [full list of AEGIS implementations](https://github.com/cfrg/draft-irtf-cfrg-aegis-aead?tab=readme-ov-file#known-implementations).

## Browser Example

A browser demo is included:

```bash
bun run build:example
open examples/index.html
```
