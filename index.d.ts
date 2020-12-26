declare module 'monocypher-wasm';

type InputBuffer = Uint8Array | readonly number[] | null;

declare function crypto_argon2i(
  hash_size: 32 | 64,
  nb_blocks: number,
  nb_iterations: number,
  password: InputBuffer,
  salt: InputBuffer,
): Uint8Array;
declare function crypto_argon2i_general(
  hash_size: 32 | 64,
  nb_blocks: number,
  nb_iterations: number,
  password: InputBuffer,
  salt: InputBuffer,
  key: InputBuffer,
  ad: InputBuffer,
): Uint8Array;

declare function crypto_blake2b(message: InputBuffer): Uint8Array;
declare function crypto_blake2b_general(hash_size: number, key: InputBuffer, message: InputBuffer): Uint8Array;

declare function crypto_chacha20(plain_text: InputBuffer, key: InputBuffer, nonce: InputBuffer): Uint8Array;
declare function crypto_xchacha20(plain_text: InputBuffer, key: InputBuffer, nonce: InputBuffer): Uint8Array;

declare function crypto_curve_to_hidden(curve: InputBuffer, tweak: number): Uint8Array | null;
declare function crypto_hidden_to_curve(hidden: InputBuffer): Uint8Array;
declare function crypto_hidden_key_pair(seed: InputBuffer): { hidden: Uint8Array, secret_key: Uint8Array };

declare function crypto_from_eddsa_private(eddsa: InputBuffer): Uint8Array;
declare function crypto_from_eddsa_public(eddsa: InputBuffer): Uint8Array;

declare function crypto_hchacha20(key: InputBuffer, in_: InputBuffer): Uint8Array;

declare function crypto_ietf_chacha20(plain_text: InputBuffer, key: InputBuffer, nonce: InputBuffer): Uint8Array;

declare function crypto_key_exchange(your_secret_key: InputBuffer, their_public_key: InputBuffer): Uint8Array;
declare function crypto_key_exchange_public_key(your_secret_key: InputBuffer): Uint8Array;

declare function crypto_lock(key: InputBuffer, nonce: InputBuffer, plain_text: InputBuffer): Uint8Array;
declare function crypto_unlock(key: InputBuffer, nonce: InputBuffer, cipher_text: InputBuffer): Uint8Array | null;
declare function crypto_lock_aead(key: InputBuffer, nonce: InputBuffer, ad: InputBuffer, plain_text: InputBuffer): Uint8Array;
declare function crypto_unlock_aead(key: InputBuffer, nonce: InputBuffer, ad: InputBuffer, cipher_text: InputBuffer): Uint8Array | null;

declare function crypto_poly1305(message: InputBuffer, key: InputBuffer): Uint8Array;

declare function crypto_sign_public_key(secret_key: InputBuffer): Uint8Array;
declare function crypto_sign(secret_key: InputBuffer, public_key: InputBuffer, message: InputBuffer): Uint8Array;
declare function crypto_check(signature: InputBuffer, public_key: InputBuffer, message: InputBuffer): boolean;

declare function crypto_verify16(a: InputBuffer, b: InputBuffer): boolean;
declare function crypto_verify32(a: InputBuffer, b: InputBuffer): boolean;
declare function crypto_verify64(a: InputBuffer, b: InputBuffer): boolean;

declare function crypto_x25519(your_secret_key: InputBuffer, their_public_key: InputBuffer): Uint8Array;
declare function crypto_x25519_public_key(your_secret_key: InputBuffer): Uint8Array;

declare function crypto_x25519_dirty_fast(sk: InputBuffer): Uint8Array;
declare function crypto_x25519_dirty_small(sk: InputBuffer): Uint8Array;

declare function crypto_x25519_inverse(private_key: InputBuffer, curve_point: InputBuffer): Uint8Array;

declare const ready: Promise<void>;
declare const HASH_BYTES: 64;
declare const KEY_BYTES: 32;
declare const NONCE_BYTES: 24;
declare const MAC_BYTES: 16;
declare const CHACHA20_NONCE_BYTES: 8;

export {
  ready,
  crypto_argon2i,
  crypto_argon2i_general,
  crypto_blake2b,
  crypto_blake2b_general,
  crypto_chacha20,
  crypto_check,
  crypto_curve_to_hidden,
  crypto_from_eddsa_private,
  crypto_from_eddsa_public,
  crypto_hchacha20,
  crypto_hidden_key_pair,
  crypto_hidden_to_curve,
  crypto_ietf_chacha20,
  crypto_key_exchange,
  crypto_key_exchange_public_key,
  crypto_lock,
  crypto_lock_aead,
  crypto_poly1305,
  crypto_sign,
  crypto_sign_public_key,
  crypto_unlock,
  crypto_unlock_aead,
  crypto_verify16,
  crypto_verify32,
  crypto_verify64,
  crypto_x25519,
  crypto_x25519_dirty_fast,
  crypto_x25519_dirty_small,
  crypto_x25519_inverse,
  crypto_x25519_public_key,
  crypto_xchacha20,
  HASH_BYTES,
  KEY_BYTES,
  NONCE_BYTES,
  MAC_BYTES,
  CHACHA20_NONCE_BYTES,
}
