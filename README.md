# Monocypher WebAssembly Port

    $ npm install monocypher-wasm

This is a JS+WASM port of [Monocypher][monocypher], a new cryptography library
similar to libsodium. It consists of a WASM-compiled Monocypher library and a JS
wrapper for functions exported by this library.

Most of Monocypher's functions are available, with the exception of the
"incremental" functions that require counters or context pointers. The APIs of
these functions have been changed to remove most length arguments, and to create
and return output buffers directly rather than taking them as arguments.

`monocypher-wasm` also provides a full Typescript definition file for its API.

## Usage

Because WebAssembly code must be loaded asynchronously, `monocypher-wasm`
exports a `ready` promise that must resolve before any Monocypher functions can
be called.

```js
const Monocypher = require('monocypher-wasm');
const { randomBytes } = require('crypto');

await Monocypher.ready;

const sk = randomBytes(Monocypher.KEY_SIZE);
const pk = Monocypher.crypto_sign_public_key(sk);
```

## API

> **Note:** An `InputBuffer` is either a `Uint8Array`, an array of numbers, or `null`.

```typescript
ready: Promise<void>

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

- `yarn build` or `npm run build` builds `monocypher.wasm` and `monocypher.js`
from `monocypher.c` and `monocypher.h`.

- `yarn test` or `npm test` runs a port of some of Monocypher's unit tests. It
uses the test vectors from Monocypher's release tarball, which have been
compiled into `test-vectors.json.gz`.

- `yarn build-from-scratch` or `npm run build-from-scratch` fetches the latest
Monocypher tarball; extracts `monocypher.c`, `monocypher.h`, and `vectors.h`
from it; and rebuilds all files that depend on them. Use this if you don't trust
my copy of Monocypher's source.

## License

Like Monocypher itself, this project is public domain, via the [CC0][cc0]
license.

[monocypher]: https://monocypher.org/
[cc0]: https://creativecommons.org/share-your-work/public-domain/cc0/
