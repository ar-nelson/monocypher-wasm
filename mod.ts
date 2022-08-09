import WASM_BIN from './monocypher_wasm.ts';

export type InputBuffer = Uint8Array | readonly number[] | null;

/**
 * For backward compatibility.
 *
 * @deprecated Not necessary in this version of `monocypher_wasm`.
 */
export const ready: Promise<void> = Promise.resolve();

interface WasmExports {
  memory: WebAssembly.Memory;
  malloc(...args: number[]): number;
  free(...args: number[]): number;
  crypto_argon2i(...args: number[]): number;
  crypto_argon2i_general(...args: number[]): number;
  crypto_blake2b(...args: number[]): number;
  crypto_blake2b_general(...args: number[]): number;
  crypto_chacha20(...args: number[]): number;
  crypto_xchacha20(...args: number[]): number;
  crypto_curve_to_hidden(...args: number[]): number;
  crypto_hidden_to_curve(...args: number[]): number;
  crypto_hidden_key_pair(...args: number[]): number;
  crypto_from_eddsa_private(...args: number[]): number;
  crypto_from_eddsa_public(...args: number[]): number;
  crypto_hchacha20(...args: number[]): number;
  crypto_ietf_chacha20(...args: number[]): number;
  crypto_key_exchange(...args: number[]): number;
  crypto_lock(...args: number[]): number;
  crypto_unlock(...args: number[]): number;
  crypto_lock_aead(...args: number[]): number;
  crypto_unlock_aead(...args: number[]): number;
  crypto_poly1305(...args: number[]): number;
  crypto_sign_public_key(...args: number[]): number;
  crypto_sign(...args: number[]): number;
  crypto_check(...args: number[]): number;
  crypto_verify16(...args: number[]): number;
  crypto_verify32(...args: number[]): number;
  crypto_verify64(...args: number[]): number;
  crypto_wipe(...args: number[]): number;
  crypto_x25519(...args: number[]): number;
  crypto_x25519_public_key(...args: number[]): number;
  crypto_x25519_dirty_fast(...args: number[]): number;
  crypto_x25519_dirty_small(...args: number[]): number;
  crypto_x25519_inverse(...args: number[]): number;
}

const instance = new WebAssembly.Instance(new WebAssembly.Module(WASM_BIN), {});
const wasm = instance.exports as unknown as WasmExports;

export const HASH_BYTES = 64;
export const KEY_BYTES = 32;
export const NONCE_BYTES = 24;
export const MAC_BYTES = 16;
export const CHACHA20_NONCE_BYTES = 8;

let allocPtr = 0, allocSize = 0, argon2iWorkArea = 0, argon2iMaxBlocks = 0;

function alloc(size: number): number {
  if (allocSize < size) {
    if (allocPtr) wasm.free(allocPtr);
    allocPtr = wasm.malloc(size);
    allocSize = size;
  }
  return allocPtr;
}

function write(value: Uint8Array | readonly number[], ptr: number, size: number = value.length) {
  const buf = new Uint8Array(wasm.memory.buffer, ptr, size);
  buf.set(value);
}

function read(ptr: number, size: number): Uint8Array {
  return new Uint8Array(wasm.memory.buffer, ptr, size).slice(0, size);
}

function updateArgon2iWorkArea(nb_blocks: number) {
  if (nb_blocks < 8) {
    throw new Error('crypto_argon2i: nb_blocks must be at least 8');
  }
  if (!argon2iWorkArea || nb_blocks > argon2iMaxBlocks) {
    if (argon2iWorkArea) {
      wasm.free(argon2iWorkArea);
    }
    argon2iWorkArea = wasm.malloc(nb_blocks * 1024);
    argon2iMaxBlocks = nb_blocks;
  }
}

export function crypto_argon2i(
  hash_size: 32 | 64,
  nb_blocks: number,
  nb_iterations: number,
  password: InputBuffer,
  salt: InputBuffer,
): Uint8Array {
  updateArgon2iWorkArea(nb_blocks);
  const passwordLength = password ? password.length : 0;
  const saltLength = salt ? salt.length : 0;
  const ptr = alloc(hash_size + passwordLength + saltLength);
  if (password) write(password, ptr + hash_size);
  if (salt) write(salt, ptr + hash_size + passwordLength);
  wasm.crypto_argon2i(
    ptr,
    hash_size,
    argon2iWorkArea,
    nb_blocks,
    nb_iterations,
    password ? (ptr + hash_size) : 0,
    passwordLength,
    salt ? (ptr + hash_size + passwordLength) : 0,
    saltLength,
  );
  return read(ptr, hash_size);
}

export function crypto_argon2i_general(
  hash_size: 32 | 64,
  nb_blocks: number,
  nb_iterations: number,
  password: InputBuffer,
  salt: InputBuffer,
  key: InputBuffer,
  ad: InputBuffer,
): Uint8Array {
  updateArgon2iWorkArea(nb_blocks);
  const passwordLength = password ? password.length : 0;
  const saltLength = salt ? salt.length : 0;
  const keyLength = key ? key.length : 0;
  const adLength = ad ? ad.length : 0;
  const ptr = alloc(hash_size + passwordLength + saltLength + keyLength + adLength);
  if (password) write(password, ptr + hash_size);
  if (salt) write(salt, ptr + hash_size + passwordLength);
  if (key) write(key, ptr + hash_size + passwordLength + saltLength);
  if (ad) write(ad, ptr + hash_size + passwordLength + saltLength + keyLength);
  wasm.crypto_argon2i_general(
    ptr,
    hash_size,
    argon2iWorkArea,
    nb_blocks,
    nb_iterations,
    password ? (ptr + hash_size) : 0,
    passwordLength,
    salt ? (ptr + hash_size + passwordLength) : 0,
    saltLength,
    key ? (ptr + hash_size + passwordLength + saltLength) : 0,
    keyLength,
    ad ? (ptr + hash_size + passwordLength + saltLength + keyLength) : 0,
    adLength,
  );
  return read(ptr, hash_size);
}

export function crypto_blake2b(message: InputBuffer): Uint8Array {
  const messageLength = message ? message.length : 0;
  const ptr = alloc(HASH_BYTES + messageLength);
  if (message) write(message, ptr + HASH_BYTES);
  wasm.crypto_blake2b(ptr, message ? ptr + HASH_BYTES : 0, messageLength);
  return read(ptr, HASH_BYTES);
}
export function crypto_blake2b_general(
  hash_size: number,
  key: InputBuffer,
  message: InputBuffer,
): Uint8Array {
  const keyLength = key ? key.length : 0;
  const messageLength = message ? message.length : 0;
  const ptr = alloc(hash_size + keyLength + messageLength);
  if (key) write(key, ptr + hash_size);
  if (message) write(message, ptr + hash_size + keyLength);
  wasm.crypto_blake2b_general(
    ptr,
    hash_size,
    key ? ptr + hash_size : 0,
    keyLength,
    message ? ptr + hash_size + keyLength : 0,
    messageLength,
  );
  return read(ptr, hash_size);
}

export function crypto_chacha20(
  plain_text: InputBuffer,
  key: InputBuffer,
  nonce: InputBuffer,
): Uint8Array {
  const textLength = plain_text ? plain_text.length : 0;
  const ptr = alloc(textLength + KEY_BYTES + CHACHA20_NONCE_BYTES);
  if (plain_text) write(plain_text, ptr);
  if (key) write(key, ptr + textLength);
  if (nonce) write(nonce, ptr + textLength + KEY_BYTES);
  wasm.crypto_chacha20(
    ptr,
    ptr,
    textLength,
    key ? ptr + textLength : 0,
    nonce ? ptr + textLength + KEY_BYTES : 0,
  );
  wasm.crypto_wipe(ptr + textLength, KEY_BYTES);
  return read(ptr, textLength);
}
export function crypto_xchacha20(
  plain_text: InputBuffer,
  key: InputBuffer,
  nonce: InputBuffer,
): Uint8Array {
  const textLength = plain_text ? plain_text.length : 0;
  const ptr = alloc(textLength + KEY_BYTES + NONCE_BYTES);
  if (plain_text) write(plain_text, ptr);
  if (key) write(key, ptr + textLength);
  if (nonce) write(nonce, ptr + textLength + KEY_BYTES);
  wasm.crypto_xchacha20(
    ptr,
    ptr,
    textLength,
    key ? ptr + textLength : 0,
    nonce ? ptr + textLength + KEY_BYTES : 0,
  );
  wasm.crypto_wipe(ptr + textLength, KEY_BYTES);
  return read(ptr, textLength);
}

export function crypto_curve_to_hidden(curve: InputBuffer, tweak: number): Uint8Array | null {
  const ptr = alloc(KEY_BYTES * 2);
  if (curve) write(curve, ptr + KEY_BYTES);
  const success = wasm.crypto_curve_to_hidden(ptr, curve ? ptr + KEY_BYTES : 0, tweak) === 0;
  wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
  return success ? read(ptr, KEY_BYTES) : null;
}
export function crypto_hidden_to_curve(hidden: InputBuffer): Uint8Array {
  const ptr = alloc(KEY_BYTES * 2);
  if (hidden) write(hidden, ptr + KEY_BYTES);
  wasm.crypto_hidden_to_curve(ptr, hidden ? ptr + KEY_BYTES : 0);
  wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
  return read(ptr, KEY_BYTES);
}
export function crypto_hidden_key_pair(
  seed: InputBuffer,
): { hidden: Uint8Array; secret_key: Uint8Array } {
  const ptr = alloc(KEY_BYTES * 3);
  if (seed) write(seed, ptr + KEY_BYTES * 2);
  wasm.crypto_hidden_key_pair(ptr, ptr + KEY_BYTES, seed ? ptr + KEY_BYTES * 2 : 0);
  const hidden = read(ptr, KEY_BYTES);
  const secret_key = read(ptr + KEY_BYTES, KEY_BYTES);
  wasm.crypto_wipe(ptr, KEY_BYTES * 3);
  return { hidden, secret_key };
}

export function crypto_from_eddsa_private(eddsa: InputBuffer): Uint8Array {
  const ptr = alloc(KEY_BYTES * 2);
  if (eddsa) write(eddsa, ptr + KEY_BYTES);
  wasm.crypto_from_eddsa_private(ptr, eddsa ? ptr + KEY_BYTES : 0);
  wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
  return read(ptr, KEY_BYTES);
}
export function crypto_from_eddsa_public(eddsa: InputBuffer): Uint8Array {
  const ptr = alloc(KEY_BYTES * 2);
  if (eddsa) write(eddsa, ptr + KEY_BYTES);
  wasm.crypto_from_eddsa_public(ptr, eddsa ? ptr + KEY_BYTES : 0);
  return read(ptr, KEY_BYTES);
}

export function crypto_hchacha20(key: InputBuffer, in_: InputBuffer): Uint8Array {
  const ptr = alloc(KEY_BYTES * 2 + 16);
  if (key) write(key, ptr + KEY_BYTES);
  if (in_) write(in_, ptr + KEY_BYTES * 2);
  wasm.crypto_hchacha20(ptr, key ? ptr + KEY_BYTES : 0, in_ ? ptr + KEY_BYTES * 2 : 0);
  wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES + 16);
  return read(ptr, KEY_BYTES);
}

export function crypto_ietf_chacha20(
  plain_text: InputBuffer,
  key: InputBuffer,
  nonce: InputBuffer,
): Uint8Array {
  const textLength = plain_text ? plain_text.length : 0;
  const ptr = alloc(textLength + KEY_BYTES + 12);
  if (plain_text) write(plain_text, ptr);
  if (key) write(key, ptr + textLength);
  if (nonce) write(nonce, ptr + textLength + KEY_BYTES);
  wasm.crypto_ietf_chacha20(
    ptr,
    ptr,
    textLength,
    key ? ptr + textLength : 0,
    nonce ? ptr + textLength + KEY_BYTES : 0,
  );
  wasm.crypto_wipe(ptr + textLength, KEY_BYTES);
  return read(ptr, textLength);
}

export function crypto_key_exchange(
  your_secret_key: InputBuffer,
  their_public_key: InputBuffer,
): Uint8Array {
  const ptr = alloc(KEY_BYTES * 3);
  if (your_secret_key) write(your_secret_key, ptr + KEY_BYTES);
  if (their_public_key) write(their_public_key, ptr + KEY_BYTES * 2);
  wasm.crypto_key_exchange(
    ptr,
    your_secret_key ? ptr + KEY_BYTES : 0,
    their_public_key ? ptr + KEY_BYTES * 2 : 0,
  );
  return read(ptr, KEY_BYTES);
}
export function crypto_key_exchange_public_key(your_secret_key: InputBuffer): Uint8Array {
  return crypto_x25519_public_key(your_secret_key);
}

export function crypto_lock(
  key: InputBuffer,
  nonce: InputBuffer,
  plain_text: InputBuffer,
): Uint8Array {
  const textLength = plain_text ? plain_text.length : 0;
  const ptr = alloc(MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES);
  if (plain_text) write(plain_text, ptr + MAC_BYTES);
  if (key) write(key, ptr + MAC_BYTES + textLength);
  if (nonce) write(nonce, ptr + MAC_BYTES + textLength + KEY_BYTES);
  wasm.crypto_lock(
    ptr,
    ptr + MAC_BYTES,
    key ? ptr + MAC_BYTES + textLength : 0,
    nonce ? ptr + MAC_BYTES + textLength + KEY_BYTES : 0,
    ptr + MAC_BYTES,
    textLength,
  );
  wasm.crypto_wipe(ptr + MAC_BYTES + textLength, KEY_BYTES);
  return read(ptr, MAC_BYTES + textLength);
}
export function crypto_unlock(
  key: InputBuffer,
  nonce: InputBuffer,
  cipher_text: InputBuffer,
): Uint8Array | null {
  if (!cipher_text || cipher_text.length < MAC_BYTES) return null;
  const textLength = cipher_text.length - MAC_BYTES;
  const ptr = alloc(MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES);
  write(cipher_text, ptr);
  if (key) write(key, ptr + MAC_BYTES + textLength);
  if (nonce) write(nonce, ptr + MAC_BYTES + textLength + KEY_BYTES);
  const success = wasm.crypto_unlock(
    ptr + MAC_BYTES,
    key ? ptr + MAC_BYTES + textLength : 0,
    nonce ? ptr + MAC_BYTES + textLength + KEY_BYTES : 0,
    ptr,
    ptr + MAC_BYTES,
    textLength,
  ) === 0;
  wasm.crypto_wipe(ptr + MAC_BYTES + textLength, KEY_BYTES);
  return success ? read(ptr + MAC_BYTES, textLength) : null;
}
export function crypto_lock_aead(
  key: InputBuffer,
  nonce: InputBuffer,
  ad: InputBuffer,
  plain_text: InputBuffer,
): Uint8Array {
  const textLength = plain_text ? plain_text.length : 0;
  const adLength = ad ? ad.length : 0;
  const ptr = alloc(MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES + adLength);
  if (plain_text) write(plain_text, ptr + MAC_BYTES);
  if (key) write(key, ptr + MAC_BYTES + textLength);
  if (nonce) write(nonce, ptr + MAC_BYTES + textLength + KEY_BYTES);
  if (ad) write(ad, ptr + MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES);
  wasm.crypto_lock_aead(
    ptr,
    ptr + MAC_BYTES,
    key ? ptr + MAC_BYTES + textLength : 0,
    nonce ? ptr + MAC_BYTES + textLength + KEY_BYTES : 0,
    ad ? ptr + MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES : 0,
    adLength,
    ptr + MAC_BYTES,
    textLength,
  );
  wasm.crypto_wipe(ptr + MAC_BYTES + textLength, KEY_BYTES);
  return read(ptr, MAC_BYTES + textLength);
}
export function crypto_unlock_aead(
  key: InputBuffer,
  nonce: InputBuffer,
  ad: InputBuffer,
  cipher_text: InputBuffer,
): Uint8Array | null {
  if (!cipher_text || cipher_text.length < MAC_BYTES) return null;
  const textLength = cipher_text.length - MAC_BYTES;
  const adLength = ad ? ad.length : 0;
  const ptr = alloc(MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES + adLength);
  write(cipher_text ?? [], ptr);
  if (key) write(key, ptr + MAC_BYTES + textLength);
  if (nonce) write(nonce, ptr + MAC_BYTES + textLength + KEY_BYTES);
  if (ad) write(ad, ptr + MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES);
  const success = wasm.crypto_unlock_aead(
    ptr + MAC_BYTES,
    key ? ptr + MAC_BYTES + textLength : 0,
    nonce ? ptr + MAC_BYTES + textLength + KEY_BYTES : 0,
    ptr,
    ad ? ptr + MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES : 0,
    adLength,
    ptr + MAC_BYTES,
    textLength,
  ) === 0;
  wasm.crypto_wipe(ptr + MAC_BYTES + textLength, KEY_BYTES);
  return success ? read(ptr + MAC_BYTES, textLength) : null;
}

export function crypto_poly1305(message: InputBuffer, key: InputBuffer): Uint8Array {
  const messageLength = message ? message.length : 0;
  const ptr = alloc(MAC_BYTES + KEY_BYTES + messageLength);
  write(key ?? [], ptr + MAC_BYTES);
  if (message) write(message, ptr + MAC_BYTES + KEY_BYTES);
  wasm.crypto_poly1305(ptr, ptr + MAC_BYTES + KEY_BYTES, messageLength, ptr + MAC_BYTES);
  return read(ptr, MAC_BYTES);
}

export function crypto_sign_public_key(secret_key: InputBuffer): Uint8Array {
  const ptr = alloc(KEY_BYTES * 2);
  if (secret_key) write(secret_key, ptr + KEY_BYTES);
  wasm.crypto_sign_public_key(ptr, secret_key ? ptr + KEY_BYTES : 0);
  wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
  return read(ptr, secret_key ? KEY_BYTES : 0);
}
export function crypto_sign(
  secret_key: InputBuffer,
  public_key: InputBuffer,
  message: InputBuffer,
): Uint8Array {
  const messageLength = message ? message.length : 0;
  const ptr = alloc(HASH_BYTES + KEY_BYTES + KEY_BYTES + messageLength);
  if (secret_key) write(secret_key, ptr + HASH_BYTES);
  if (public_key) write(public_key, ptr + HASH_BYTES + KEY_BYTES);
  if (message) write(message, ptr + HASH_BYTES + KEY_BYTES * 2);
  wasm.crypto_sign(
    ptr,
    secret_key ? ptr + HASH_BYTES : 0,
    public_key ? ptr + HASH_BYTES + KEY_BYTES : 0,
    message ? ptr + HASH_BYTES + KEY_BYTES * 2 : 0,
    messageLength,
  );
  wasm.crypto_wipe(ptr + HASH_BYTES + KEY_BYTES, KEY_BYTES);
  return read(ptr, HASH_BYTES);
}
export function crypto_check(
  signature: InputBuffer,
  public_key: InputBuffer,
  message: InputBuffer,
): boolean {
  const messageLength = message ? message.length : 0;
  const ptr = alloc(HASH_BYTES + KEY_BYTES + messageLength);
  if (signature) write(signature, ptr, HASH_BYTES);
  if (public_key) write(public_key, ptr + HASH_BYTES, KEY_BYTES);
  if (message) write(message, ptr + HASH_BYTES + KEY_BYTES, messageLength);
  return wasm.crypto_check(
    signature ? ptr : 0,
    public_key ? ptr + HASH_BYTES : 0,
    message ? ptr + HASH_BYTES + KEY_BYTES : 0,
    messageLength,
  ) === 0;
}

export function crypto_verify16(a: InputBuffer, b: InputBuffer): boolean {
  const ptr = alloc(32);
  write(a ?? [], ptr);
  write(b ?? [], ptr + 16);
  return wasm.crypto_verify16(ptr, ptr + 16) === 0;
}
export function crypto_verify32(a: InputBuffer, b: InputBuffer): boolean {
  const ptr = alloc(64);
  write(a ?? [], ptr);
  write(b ?? [], ptr + 32);
  return wasm.crypto_verify32(ptr, ptr + 32) === 0;
}
export function crypto_verify64(a: InputBuffer, b: InputBuffer): boolean {
  const ptr = alloc(128);
  write(a ?? [], ptr);
  write(b ?? [], ptr + 64);
  return wasm.crypto_verify64(ptr, ptr + 64) === 0;
}

export function crypto_x25519(
  your_secret_key: InputBuffer,
  their_public_key: InputBuffer,
): Uint8Array {
  const ptr = alloc(KEY_BYTES * 3);
  if (your_secret_key) write(your_secret_key, ptr + KEY_BYTES);
  if (their_public_key) write(their_public_key, ptr + KEY_BYTES * 2);
  wasm.crypto_x25519(
    ptr,
    your_secret_key ? ptr + KEY_BYTES : 0,
    their_public_key ? ptr + KEY_BYTES * 2 : 0,
  );
  return read(ptr, KEY_BYTES);
}
export function crypto_x25519_public_key(secret_key: InputBuffer): Uint8Array {
  const ptr = alloc(KEY_BYTES * 2);
  if (secret_key) write(secret_key, ptr + KEY_BYTES);
  wasm.crypto_x25519_public_key(ptr, secret_key ? ptr + KEY_BYTES : 0);
  wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
  return read(ptr, KEY_BYTES);
}

export function crypto_x25519_dirty_fast(secret_key: InputBuffer): Uint8Array {
  const ptr = alloc(KEY_BYTES * 2);
  if (secret_key) write(secret_key, ptr + KEY_BYTES);
  wasm.crypto_x25519_dirty_fast(ptr, secret_key ? ptr + KEY_BYTES : 0);
  wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
  return read(ptr, KEY_BYTES);
}
export function crypto_x25519_dirty_small(secret_key: InputBuffer): Uint8Array {
  const ptr = alloc(KEY_BYTES * 2);
  if (secret_key) write(secret_key, ptr + KEY_BYTES);
  wasm.crypto_x25519_dirty_small(ptr, secret_key ? ptr + KEY_BYTES : 0);
  wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
  return read(ptr, KEY_BYTES);
}

export function crypto_x25519_inverse(
  private_key: InputBuffer,
  curve_point: InputBuffer,
): Uint8Array {
  const ptr = alloc(KEY_BYTES * 3);
  if (private_key) write(private_key, ptr + KEY_BYTES);
  if (curve_point) write(curve_point, ptr + KEY_BYTES * 2);
  wasm.crypto_x25519_inverse(
    ptr,
    private_key ? ptr + KEY_BYTES : 0,
    curve_point ? ptr + KEY_BYTES * 2 : 0,
  );
  wasm.crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
  return read(ptr, KEY_BYTES);
}
