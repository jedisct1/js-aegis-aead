# aegis-aead

[![npm](https://img.shields.io/npm/v/aegis-aead)](https://www.npmjs.com/package/aegis-aead)
[![CI](https://github.com/jedisct1/js-aegis-aead/actions/workflows/ci.yml/badge.svg)](https://github.com/jedisct1/js-aegis-aead/actions/workflows/ci.yml)

JavaScript / TypeScript implementation of the [AEGIS authenticated encryption algorithms](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/).

AEGIS is a family of fast authenticated encryption algorithms built on AES round functions. It provides both encryption with authentication and standalone MAC functionality.

## Installation

```bash
bun add aegis-aead
# or
npm install aegis-aead
```

## Usage

### Encryption and Decryption

```typescript
import { aegis128LEncrypt, aegis128LDecrypt } from "aegis-aead";

const key = crypto.getRandomValues(new Uint8Array(16));
const nonce = crypto.getRandomValues(new Uint8Array(16));
const message = new TextEncoder().encode("Hello, world!");
const associatedData = new TextEncoder().encode("metadata");

// Encrypt
const { ciphertext, tag } = aegis128LEncrypt(message, associatedData, key, nonce);

// Decrypt (returns null if authentication fails)
const decrypted = aegis128LDecrypt(ciphertext, tag, associatedData, key, nonce);
```

### MAC (Message Authentication Code)

```typescript
import { aegis128LMac, aegis128LMacVerify } from "aegis-aead";

const key = crypto.getRandomValues(new Uint8Array(16));
const nonce = crypto.getRandomValues(new Uint8Array(16));
const data = new TextEncoder().encode("data to authenticate");

// Generate MAC
const tag = aegis128LMac(data, key, nonce);

// Verify MAC
const valid = aegis128LMacVerify(data, tag, key, nonce);
```

## Algorithms

| Algorithm  | Key Size | Nonce Size | Block Size | Use Case                           |
| ---------- | -------- | ---------- | ---------- | ---------------------------------- |
| AEGIS-128L | 16 bytes | 16 bytes   | 32 bytes   | High throughput on 64-bit CPUs     |
| AEGIS-256  | 32 bytes | 32 bytes   | 16 bytes   | 256-bit security level             |
| AEGIS-128X | 16 bytes | 16 bytes   | 32×D bytes | Multi-lane AEGIS-128L (D = degree) |
| AEGIS-256X | 32 bytes | 32 bytes   | 16×D bytes | Multi-lane AEGIS-256 (D = degree)  |

### Tag Lengths

All algorithms support two tag lengths:
- 16 bytes (128-bit) - default
- 32 bytes (256-bit) - pass `32` as the last parameter to encrypt/MAC functions

## API Reference

### AEGIS-128L

```typescript
aegis128LEncrypt(msg, ad, key, nonce, tagLen?): { ciphertext, tag }
aegis128LDecrypt(ciphertext, tag, ad, key, nonce): Uint8Array | null
aegis128LMac(data, key, nonce, tagLen?): Uint8Array
aegis128LMacVerify(data, tag, key, nonce): boolean
```

### AEGIS-256

```typescript
aegis256Encrypt(msg, ad, key, nonce, tagLen?): { ciphertext, tag }
aegis256Decrypt(ciphertext, tag, ad, key, nonce): Uint8Array | null
aegis256Mac(data, key, nonce, tagLen?): Uint8Array
aegis256MacVerify(data, tag, key, nonce): boolean
```

### AEGIS-128X

Pre-configured variants for degree 2 and 4:

```typescript
// Degree 2
aegis128X2Encrypt(msg, ad, key, nonce, tagLen?): { ciphertext, tag }
aegis128X2Decrypt(ciphertext, tag, ad, key, nonce): Uint8Array | null
aegis128X2Mac(data, key, nonce, tagLen?): Uint8Array
aegis128X2MacVerify(data, tag, key, nonce): boolean

// Degree 4
aegis128X4Encrypt(msg, ad, key, nonce, tagLen?): { ciphertext, tag }
aegis128X4Decrypt(ciphertext, tag, ad, key, nonce): Uint8Array | null
aegis128X4Mac(data, key, nonce, tagLen?): Uint8Array
aegis128X4MacVerify(data, tag, key, nonce): boolean

// Custom degree
aegis128XEncrypt(msg, ad, key, nonce, tagLen?, degree?): { ciphertext, tag }
aegis128XDecrypt(ciphertext, tag, ad, key, nonce, degree?): Uint8Array | null
aegis128XMac(data, key, nonce, tagLen?, degree?): Uint8Array
aegis128XMacVerify(data, tag, key, nonce, degree?): boolean
```

### AEGIS-256X

Pre-configured variants for degree 2 and 4:

```typescript
// Degree 2
aegis256X2Encrypt(msg, ad, key, nonce, tagLen?): { ciphertext, tag }
aegis256X2Decrypt(ciphertext, tag, ad, key, nonce): Uint8Array | null
aegis256X2Mac(data, key, nonce, tagLen?): Uint8Array
aegis256X2MacVerify(data, tag, key, nonce): boolean

// Degree 4
aegis256X4Encrypt(msg, ad, key, nonce, tagLen?): { ciphertext, tag }
aegis256X4Decrypt(ciphertext, tag, ad, key, nonce): Uint8Array | null
aegis256X4Mac(data, key, nonce, tagLen?): Uint8Array
aegis256X4MacVerify(data, tag, key, nonce): boolean

// Custom degree
aegis256XEncrypt(msg, ad, key, nonce, tagLen?, degree?): { ciphertext, tag }
aegis256XDecrypt(ciphertext, tag, ad, key, nonce, degree?): Uint8Array | null
aegis256XMac(data, key, nonce, tagLen?, degree?): Uint8Array
aegis256XMacVerify(data, tag, key, nonce, degree?): boolean
```

## Browser Example

A browser example is included in `examples/`. To build and run it:

```bash
bun run build:example
open examples/index.html
```

The example demonstrates encryption/decryption with a simple UI where you can enter a message, encrypt it, and decrypt it back.

## License

MIT
