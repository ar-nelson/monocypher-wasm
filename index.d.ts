declare module 'monocypher-wasm';

type InputBuffer = Uint8Array | readonly number[] | null;

declare interface MonocypherModule {
  crypto_argon2i(
    hash_size: 32 | 64,
    nb_blocks: number,
    nb_iterations: number,
    password: InputBuffer,
    salt: InputBuffer,
  ): Uint8Array;
  crypto_argon2i_general(
    hash_size: 32 | 64,
    nb_blocks: number,
    nb_iterations: number,
    password: InputBuffer,
    salt: InputBuffer,
    key: InputBuffer,
    ad: InputBuffer,
  ): Uint8Array;

  crypto_blake2b(message: InputBuffer): Uint8Array;
  crypto_blake2b_general(hash_size: number, key: InputBuffer, message: InputBuffer): Uint8Array;

  crypto_chacha20(plain_text: InputBuffer, key: InputBuffer, nonce: InputBuffer): Uint8Array;
  crypto_xchacha20(plain_text: InputBuffer, key: InputBuffer, nonce: InputBuffer): Uint8Array;

  crypto_curve_to_hidden(curve: InputBuffer, tweak: number): Uint8Array | null;
  crypto_hidden_to_curve(hidden: InputBuffer): Uint8Array;
  crypto_hidden_key_pair(seed: InputBuffer): { hidden: Uint8Array, secret_key: Uint8Array };

  crypto_from_eddsa_private(eddsa: InputBuffer): Uint8Array;
  crypto_from_eddsa_public(eddsa: InputBuffer): Uint8Array;

  crypto_hchacha20(key: InputBuffer, in_: InputBuffer): Uint8Array;

  crypto_ietf_chacha20(plain_text: InputBuffer, key: InputBuffer, nonce: InputBuffer): Uint8Array;

  crypto_key_exchange(your_secret_key: InputBuffer, their_public_key: InputBuffer): Uint8Array;
  crypto_key_exchange_public_key(your_secret_key: InputBuffer): Uint8Array;

  crypto_lock(key: InputBuffer, plain_text: InputBuffer): Uint8Array;
  crypto_unlock(key: InputBuffer, nonce: InputBuffer, cipher_text: InputBuffer): Uint8Array | null;
  crypto_lock_aead(key: InputBuffer, ad: InputBuffer, plain_text: InputBuffer): Uint8Array;
  crypto_unlock_aead(key: InputBuffer, nonce: InputBuffer, ad: InputBuffer, cipher_text: InputBuffer): Uint8Array | null;

  crypto_poly1305(message: InputBuffer, key: InputBuffer): Uint8Array;

  crypto_sign_public_key(secret_key: InputBuffer): Uint8Array;
  crypto_sign(secret_key: InputBuffer, public_key: InputBuffer, message: InputBuffer): Uint8Array;
  crypto_check(signature: InputBuffer, public_key: InputBuffer, message: InputBuffer): boolean;

  crypto_verify16(a: InputBuffer, b: InputBuffer): boolean;
  crypto_verify32(a: InputBuffer, b: InputBuffer): boolean;
  crypto_verify64(a: InputBuffer, b: InputBuffer): boolean;

  crypto_x25519(your_secret_key: InputBuffer, their_public_key: InputBuffer): Uint8Array;
  crypto_x25519_public_key(your_secret_key: InputBuffer): Uint8Array;

  crypto_x25519_dirty_fast(sk: InputBuffer): Uint8Array;
  crypto_x25519_dirty_small(sk: InputBuffer): Uint8Array;

  crypto_x25519_inverse(private_key: InputBuffer, curve_point: InputBuffer): Uint8Array;
}

declare const Monocypher: Promise<MonocypherModule>;
declare const HASH_BYTES: 64;
declare const KEY_BYTES: 32;
declare const NONCE_BYTES: 24;
declare const MAC_BYTES: 16;
declare const CHACHA20_NONCE_BYTES: 8;

export {
  Monocypher,
  HASH_BYTES,
  KEY_BYTES,
  NONCE_BYTES,
  MAC_BYTES,
  CHACHA20_NONCE_BYTES,
}
