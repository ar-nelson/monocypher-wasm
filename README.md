# Monocypher WebAssembly Port

This is a Typescript+WASM port of [Monocypher][monocypher], a new cryptography library similar to
libsodium. It consists of a WASM-compiled Monocypher library and a Typescript wrapper for functions
exported by this library.

Most of Monocypher's functions are available, with the exception of the "incremental" functions that
require counters or context pointers. The APIs of these functions have been changed to remove most
length arguments, and to create and return output buffers directly rather than taking them as
arguments.

## Usage

Monocypher can be used from Node, Deno, and the browser:

```javascript
// Node
const { crypto_blake2b } = require('monocypher-wasm');

// Deno
import { crypto_blake2b } from 'https://deno.land/x/monocypher@v3.1.2-4/mod.ts';

// Browser (only 24KB gzipped!)
import { crypto_blake2b } from 'https://raw.githubusercontent.com/ar-nelson/monocypher-wasm/v3.1.2-4/monocypher.min.js';
```

Unlike previous versions of this package, the API is synchronous, and no `ready` promise is needed.
`ready` is still included for backward compatibility.

## API

> **Note:** An `InputBuffer` is either a `Uint8Array`, an array of numbers, or `null`.

```typescript
crypto_blake2b(message: InputBuffer): Uint8Array
crypto_blake2b_general(hash_size: number, key: InputBuffer, message: InputBuffer): Uint8Array

crypto_chacha20(plain_text: InputBuffer, key: InputBuffer, nonce: InputBuffer): Uint8Array
crypto_xchacha20(plain_text: InputBuffer, key: InputBuffer, nonce: InputBuffer): Uint8Array

// crypto_curve_to_hidden returns null on failure
crypto_curve_to_hidden(curve: InputBuffer, tweak: number): Uint8Array | null
crypto_hidden_to_curve(hidden: InputBuffer): Uint8Array
crypto_hidden_key_pair(seed: InputBuffer): { hidden: Uint8Array, secret_key: Uint8Array }

crypto_from_eddsa_private(eddsa: InputBuffer): Uint8Array
crypto_from_eddsa_public(eddsa: InputBuffer): Uint8Array

crypto_hchacha20(key: InputBuffer, in_: InputBuffer): Uint8Array

crypto_ietf_chacha20(plain_text: InputBuffer, key: InputBuffer, nonce: InputBuffer): Uint8Array

crypto_key_exchange(your_secret_key: InputBuffer, their_public_key: InputBuffer): Uint8Array
crypto_key_exchange_public_key(your_secret_key: InputBuffer): Uint8Array

// crypto_unlock functions return null on failure
crypto_lock(key: InputBuffer, nonce: InputBuffer, plain_text: InputBuffer): Uint8Array
crypto_unlock(key: InputBuffer, nonce: InputBuffer, cipher_text: InputBuffer): Uint8Array | null
crypto_lock_aead(key: InputBuffer, nonce: InputBuffer, ad: InputBuffer, plain_text: InputBuffer): Uint8Array
crypto_unlock_aead(key: InputBuffer, nonce: InputBuffer, ad: InputBuffer, cipher_text: InputBuffer): Uint8Array | null

crypto_poly1305(message: InputBuffer, key: InputBuffer): Uint8Array

crypto_sign_public_key(secret_key: InputBuffer): Uint8Array
crypto_sign(secret_key: InputBuffer, public_key: InputBuffer, message: InputBuffer): Uint8Array
crypto_check(signature: InputBuffer, public_key: InputBuffer, message: InputBuffer): boolean

crypto_verify16(a: InputBuffer, b: InputBuffer): boolean
crypto_verify32(a: InputBuffer, b: InputBuffer): boolean
crypto_verify64(a: InputBuffer, b: InputBuffer): boolean

crypto_x25519(your_secret_key: InputBuffer, their_public_key: InputBuffer): Uint8Array
crypto_x25519_public_key(your_secret_key: InputBuffer): Uint8Array

crypto_x25519_dirty_fast(sk: InputBuffer): Uint8Array
crypto_x25519_dirty_small(sk: InputBuffer): Uint8Array

crypto_x25519_inverse(private_key: InputBuffer, curve_point: InputBuffer): Uint8Array

HASH_BYTES: 64
KEY_BYTES: 32
NONCE_BYTES: 24
MAC_BYTES: 16
CHACHA20_NONCE_BYTES: 8
```

## Compilation and Testing

The repo contains the Deno (`mod.ts`) and browser (`monocypher.min.js`) modules. The Node module
must be built with `dnt`.

The build process is defined in a GNU Makefile.

`make` will rebuild everything, including the Node module, and run tests in both Deno and Node. It
will even redownload the Monocypher sources from [monocypher.org][monocypher].

`make` requires `clang`, `lld`, `deno`, `npm`, `esbuild`, `curl`, and a Unix environment.

## License

Like Monocypher itself, this project is public domain, via the [CC0][cc0] license.

This project contains code from [`wingo/walloc`][walloc], which is available under
[a permissive MIT-style license][walloc-license].

[monocypher]: https://monocypher.org/
[cc0]: https://creativecommons.org/share-your-work/public-domain/cc0/
[walloc]: https://github.com/wingo/walloc
[walloc-license]: https://github.com/wingo/walloc/blob/a93409f5ebd49c875514c5fee30d3b151f7b0882/LICENSE.md
