# aegis-aead

[![npm](https://img.shields.io/npm/v/aegis-aead)](https://www.npmjs.com/package/aegis-aead)
[![CI](https://github.com/jedisct1/js-aegis-aead/actions/workflows/ci.yml/badge.svg)](https://github.com/jedisct1/js-aegis-aead/actions/workflows/ci.yml)

A pure, zero-dependencies JavaScript/TypeScript implementation of [AEGIS](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/), a new family of secure, high-performance authenticated encryption algorithms.

AEGIS provides both encryption with authentication and standalone MAC functionality, with a simple API that makes it hard to misuse.

## Installation

```bash
bun add aegis-aead
# or
npm install aegis-aead
```

## Usage

### Encryption and Decryption

```typescript
import {
  aegis128LCreateKey,
  aegis128LEncrypt,
  aegis128LDecrypt
} from "aegis-aead";

const key = aegis128LCreateKey(); // 16 random bytes
const message = new TextEncoder().encode("Hello, world!");
const associatedData = new TextEncoder().encode("metadata");

// Encrypt - returns nonce || ciphertext || tag
// A random nonce is generated automatically
const sealed = aegis128LEncrypt(message, associatedData, key);

// Decrypt (returns null if authentication fails)
const decrypted = aegis128LDecrypt(sealed, associatedData, key);
```

### Detached Mode

For applications that need separate access to the ciphertext and tag:

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
const associatedData = new TextEncoder().encode("metadata");

// Encrypt - returns ciphertext and tag separately
const { ciphertext, tag } = aegis128LEncryptDetached(message, associatedData, key, nonce);

// Decrypt
const decrypted = aegis128LDecryptDetached(ciphertext, tag, associatedData, key, nonce);
```

### MAC (Message Authentication Code)

```typescript
import {
  aegis128LCreateKey,
  aegis128LMac,
  aegis128LMacVerify
} from "aegis-aead";

const key = aegis128LCreateKey();
const data = new TextEncoder().encode("data to authenticate");

// Generate MAC (nonce defaults to zero if not provided)
const tag = aegis128LMac(data, key);

// Verify MAC
const valid = aegis128LMacVerify(data, tag, key);
```

## Algorithms

| Algorithm  | Key Size | Nonce Size | Block Size | Use Case                           |
| ---------- | -------- | ---------- | ---------- | ---------------------------------- |
| AEGIS-128L | 16 bytes | 16 bytes   | 32 bytes   | High throughput on 64-bit CPUs     |
| AEGIS-256  | 32 bytes | 32 bytes   | 16 bytes   | 256-bit security level             |
| AEGIS-128X | 16 bytes | 16 bytes   | 32×D bytes | Multi-lane AEGIS-128L (D = degree) |
| AEGIS-256X | 32 bytes | 32 bytes   | 16×D bytes | Multi-lane AEGIS-256 (D = degree)  |

### Random Nonces

When using random nonces (the default for combined-mode functions):

- AEGIS-128L/128X: Safe for up to 2^48 messages per key, regardless of their size
- AEGIS-256/256X: No practical limits on the number of messages per key

### Tag Lengths

All algorithms support two tag lengths:
- 16 bytes (128-bit) - default
- 32 bytes (256-bit) - pass `32` as the last parameter to encrypt/MAC functions

## API Reference

### AEGIS-128L

```typescript
// Key/Nonce generation
aegis128LCreateKey(): Uint8Array   // 16 random bytes
aegis128LCreateNonce(): Uint8Array // 16 random bytes

// Combined (nonce || ciphertext || tag)
aegis128LEncrypt(msg, ad, key, nonce?, tagLen?): Uint8Array
aegis128LDecrypt(sealed, ad, key, tagLen?): Uint8Array | null

// Detached (separate ciphertext and tag)
aegis128LEncryptDetached(msg, ad, key, nonce, tagLen?): { ciphertext, tag }
aegis128LDecryptDetached(ciphertext, tag, ad, key, nonce): Uint8Array | null

// MAC (nonce is optional, defaults to zero)
aegis128LMac(data, key, nonce?, tagLen?): Uint8Array
aegis128LMacVerify(data, tag, key, nonce?): boolean

// Constants
AEGIS_128L_KEY_SIZE   // 16
AEGIS_128L_NONCE_SIZE // 16
```

### AEGIS-256

```typescript
// Key/Nonce generation
aegis256CreateKey(): Uint8Array   // 32 random bytes
aegis256CreateNonce(): Uint8Array // 32 random bytes

// Combined (nonce || ciphertext || tag)
aegis256Encrypt(msg, ad, key, nonce?, tagLen?): Uint8Array
aegis256Decrypt(sealed, ad, key, tagLen?): Uint8Array | null

// Detached (separate ciphertext and tag)
aegis256EncryptDetached(msg, ad, key, nonce, tagLen?): { ciphertext, tag }
aegis256DecryptDetached(ciphertext, tag, ad, key, nonce): Uint8Array | null

// MAC (nonce is optional, defaults to zero)
aegis256Mac(data, key, nonce?, tagLen?): Uint8Array
aegis256MacVerify(data, tag, key, nonce?): boolean

// Constants
AEGIS_256_KEY_SIZE   // 32
AEGIS_256_NONCE_SIZE // 32
```

### AEGIS-128X

Pre-configured variants for degree 2 and 4:

```typescript
// Key/Nonce generation
aegis128XCreateKey(): Uint8Array   // 16 random bytes
aegis128XCreateNonce(): Uint8Array // 16 random bytes
aegis128X2CreateKey(): Uint8Array  // alias
aegis128X2CreateNonce(): Uint8Array
aegis128X4CreateKey(): Uint8Array  // alias
aegis128X4CreateNonce(): Uint8Array

// Combined (nonce || ciphertext || tag)
aegis128X2Encrypt(msg, ad, key, nonce?, tagLen?): Uint8Array
aegis128X2Decrypt(sealed, ad, key, tagLen?): Uint8Array | null
aegis128X4Encrypt(msg, ad, key, nonce?, tagLen?): Uint8Array
aegis128X4Decrypt(sealed, ad, key, tagLen?): Uint8Array | null

// Detached (separate ciphertext and tag)
aegis128X2EncryptDetached(msg, ad, key, nonce, tagLen?): { ciphertext, tag }
aegis128X2DecryptDetached(ciphertext, tag, ad, key, nonce): Uint8Array | null
aegis128X4EncryptDetached(msg, ad, key, nonce, tagLen?): { ciphertext, tag }
aegis128X4DecryptDetached(ciphertext, tag, ad, key, nonce): Uint8Array | null

// MAC (nonce is optional, defaults to zero)
aegis128X2Mac(data, key, nonce?, tagLen?): Uint8Array
aegis128X2MacVerify(data, tag, key, nonce?): boolean
aegis128X4Mac(data, key, nonce?, tagLen?): Uint8Array
aegis128X4MacVerify(data, tag, key, nonce?): boolean

// Custom degree
aegis128XEncrypt(msg, ad, key, nonce?, tagLen?, degree?): Uint8Array
aegis128XDecrypt(sealed, ad, key, tagLen?, degree?): Uint8Array | null
aegis128XEncryptDetached(msg, ad, key, nonce, tagLen?, degree?): { ciphertext, tag }
aegis128XDecryptDetached(ciphertext, tag, ad, key, nonce, degree?): Uint8Array | null
aegis128XMac(data, key, nonce?, tagLen?, degree?): Uint8Array
aegis128XMacVerify(data, tag, key, nonce?, degree?): boolean

// Constants
AEGIS_128X_KEY_SIZE   // 16
AEGIS_128X_NONCE_SIZE // 16
```

### AEGIS-256X

Pre-configured variants for degree 2 and 4:

```typescript
// Key/Nonce generation
aegis256XCreateKey(): Uint8Array   // 32 random bytes
aegis256XCreateNonce(): Uint8Array // 32 random bytes
aegis256X2CreateKey(): Uint8Array  // alias
aegis256X2CreateNonce(): Uint8Array
aegis256X4CreateKey(): Uint8Array  // alias
aegis256X4CreateNonce(): Uint8Array

// Combined (nonce || ciphertext || tag)
aegis256X2Encrypt(msg, ad, key, nonce?, tagLen?): Uint8Array
aegis256X2Decrypt(sealed, ad, key, tagLen?): Uint8Array | null
aegis256X4Encrypt(msg, ad, key, nonce?, tagLen?): Uint8Array
aegis256X4Decrypt(sealed, ad, key, tagLen?): Uint8Array | null

// Detached (separate ciphertext and tag)
aegis256X2EncryptDetached(msg, ad, key, nonce, tagLen?): { ciphertext, tag }
aegis256X2DecryptDetached(ciphertext, tag, ad, key, nonce): Uint8Array | null
aegis256X4EncryptDetached(msg, ad, key, nonce, tagLen?): { ciphertext, tag }
aegis256X4DecryptDetached(ciphertext, tag, ad, key, nonce): Uint8Array | null

// MAC (nonce is optional, defaults to zero)
aegis256X2Mac(data, key, nonce?, tagLen?): Uint8Array
aegis256X2MacVerify(data, tag, key, nonce?): boolean
aegis256X4Mac(data, key, nonce?, tagLen?): Uint8Array
aegis256X4MacVerify(data, tag, key, nonce?): boolean

// Custom degree
aegis256XEncrypt(msg, ad, key, nonce?, tagLen?, degree?): Uint8Array
aegis256XDecrypt(sealed, ad, key, tagLen?, degree?): Uint8Array | null
aegis256XEncryptDetached(msg, ad, key, nonce, tagLen?, degree?): { ciphertext, tag }
aegis256XDecryptDetached(ciphertext, tag, ad, key, nonce, degree?): Uint8Array | null
aegis256XMac(data, key, nonce?, tagLen?, degree?): Uint8Array
aegis256XMacVerify(data, tag, key, nonce?, degree?): boolean

// Constants
AEGIS_256X_KEY_SIZE   // 32
AEGIS_256X_NONCE_SIZE // 32
```

## Browser Example

A browser example is included in `examples/`. To build and run it:

```bash
bun run build:example
open examples/index.html
```

The example demonstrates encryption/decryption with a simple UI where you can enter a message, encrypt it, and decrypt it back.

## Compatibility

The key/nonce generation functions use the Web Crypto API (`globalThis.crypto.getRandomValues`) which is available in:

- All modern browsers
- Node.js 18+
- Deno
- Bun

## Interoperability

This library follows the [AEGIS IETF draft specification](https://datatracker.ietf.org/doc/draft-irtf-cfrg-aegis-aead/) and can exchange encrypted messages with any compliant implementation, including native libraries in C, Rust, Go, Zig, and more.

See the [full list of AEGIS implementations](https://github.com/cfrg/draft-irtf-cfrg-aegis-aead?tab=readme-ov-file#known-implementations).

## License

MIT
