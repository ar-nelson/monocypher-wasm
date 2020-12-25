const loadMonocypher = require('./monocypher');
const HASH_BYTES = 64;
const KEY_BYTES = 32;
const MAC_BYTES = 16;
const NONCE_BYTES = 24;
const CHACHA20_NONCE_BYTES = 8;

let wasm;
let argon2iWorkArea = 0;
let argon2iMaxBlocks = 0;

const ready = loadMonocypher().then((module) => {
  wasm = module;
});

function assertReady() {
  if (!wasm) {
    throw new Error('Monocypher.ready must resolve before Monocypher functions can be used');
  }
}

function updateArgon2iWorkArea(nb_blocks, nb_iterations) {
  if (nb_blocks < 8) {
    throw new Error("crypto_argon2i: nb_blocks must be at least 8");
  }
  if (!argon2iWorkArea || nb_blocks > argon2iMaxBlocks) {
    if (argon2iWorkArea) {
      wasm._free(argon2iWorkArea);
    }
    argon2iWorkArea = wasm._malloc(nb_blocks * 1024);
    argon2iMaxBlocks = nb_blocks;
  }
}

function crypto_argon2i(hash_size, nb_blocks, nb_iterations, password, salt) {
  assertReady();
  updateArgon2iWorkArea(nb_blocks, nb_iterations);
  const passwordLength = password ? password.byteLength : 0;
  const saltLength = salt ? salt.byteLength : 0;
  const ptr = wasm._malloc(hash_size + passwordLength + saltLength);
  if (password) wasm.HEAPU8.set(password, ptr + hash_size);
  if (salt) wasm.HEAPU8.set(salt, ptr + hash_size + passwordLength);
  wasm._crypto_argon2i(
    ptr, hash_size,
    argon2iWorkArea, nb_blocks, nb_iterations,
    password && (ptr + hash_size), passwordLength,
    salt && (ptr + hash_size + passwordLength), saltLength
  );
  const out = wasm.HEAPU8.slice(ptr, ptr + hash_size);
  wasm._free(ptr);
  return out;
}

function crypto_argon2i_general(hash_size, nb_blocks, nb_iterations, password, salt, key, ad) {
  assertReady();
  updateArgon2iWorkArea(nb_blocks, nb_iterations);
  const passwordLength = password ? password.byteLength : 0;
  const saltLength = salt ? salt.byteLength : 0;
  const keyLength = key ? key.byteLength : 0;
  const adLength = ad ? ad.byteLength : 0;
  const ptr = wasm._malloc(hash_size + passwordLength + saltLength + keyLength + adLength);
  if (password) wasm.HEAPU8.set(password, ptr + hash_size);
  if (salt) wasm.HEAPU8.set(salt, ptr + hash_size + passwordLength);
  if (key) wasm.HEAPU8.set(key, ptr + hash_size + passwordLength + saltLength);
  if (ad) wasm.HEAPU8.set(ad, ptr + hash_size + passwordLength + saltLength + keyLength);
  wasm._crypto_argon2i_general(
    ptr, hash_size,
    argon2iWorkArea, nb_blocks, nb_iterations,
    password && (ptr + hash_size), passwordLength,
    salt && (ptr + hash_size + passwordLength), saltLength,
    key && (ptr + hash_size + passwordLength + saltLength), keyLength,
    ad && (ptr + hash_size + passwordLength + saltLength + keyLength), adLength
  );
  const out = wasm.HEAPU8.slice(ptr, ptr + hash_size);
  wasm._free(ptr);
  return out;
}

function crypto_blake2b(message) {
  assertReady();
  const messageLength = message ? message.byteLength : 0;
  const ptr = wasm._malloc(HASH_BYTES + messageLength);
  if (message) wasm.HEAPU8.set(message, ptr + HASH_BYTES);
  wasm._crypto_blake2b(ptr, message && (ptr + HASH_BYTES), messageLength);
  const out = wasm.HEAPU8.slice(ptr, ptr + HASH_BYTES);
  wasm._free(ptr);
  return out;
}
function crypto_blake2b_general(hash_size, key, message) {
  assertReady();
  const keyLength = key ? key.byteLength : 0;
  const messageLength = message ? message.byteLength : 0;
  const ptr = wasm._malloc(hash_size + keyLength + messageLength);
  if (key) wasm.HEAPU8.set(key, ptr + hash_size);
  if (message) wasm.HEAPU8.set(message, ptr + hash_size + keyLength);
  wasm._crypto_blake2b_general(
    ptr, hash_size,
    key && (ptr + hash_size), keyLength,
    message && (ptr + hash_size + keyLength), messageLength
  );
  const out = wasm.HEAPU8.slice(ptr, ptr + hash_size);
  wasm._free(ptr);
  return out;
}

function crypto_chacha20(plain_text, key, nonce) {
  assertReady();
  const textLength = plain_text ? plain_text.byteLength : 0;
  const ptr = wasm._malloc(textLength + KEY_BYTES + CHACHA20_NONCE_BYTES);
  if (plain_text) wasm.HEAPU8.set(plain_text, ptr);
  if (key) wasm.HEAPU8.set(key, ptr + textLength, KEY_BYTES);
  if (nonce) wasm.HEAPU8.set(nonce, ptr + textLength + KEY_BYTES, CHACHA20_NONCE_BYTES);
  wasm._crypto_chacha20(
    ptr, ptr, textLength,
    key && (ptr + textLength),
    nonce && (ptr + textLength + KEY_BYTES)
  );
  const out = wasm.HEAPU8.slice(ptr, ptr + textLength);
  wasm._crypto_wipe(ptr + textLength, KEY_BYTES);
  wasm._free(ptr);
  return out;
}
function crypto_xchacha20(plain_text, key, nonce) {
  assertReady();
  const textLength = plain_text ? plain_text.byteLength : 0;
  const ptr = wasm._malloc(textLength + KEY_BYTES + NONCE_BYTES);
  if (plain_text) wasm.HEAPU8.set(plain_text, ptr);
  if (key) wasm.HEAPU8.set(key, ptr + textLength, KEY_BYTES);
  if (nonce) wasm.HEAPU8.set(nonce, ptr + textLength + KEY_BYTES, NONCE_BYTES);
  wasm._crypto_xchacha20(
    ptr, ptr, textLength,
    key && (ptr + textLength),
    nonce && (ptr + textLength + KEY_BYTES)
  );
  const out = wasm.HEAPU8.slice(ptr, ptr + textLength);
  wasm._crypto_wipe(ptr + textLength, KEY_BYTES);
  wasm._free(ptr);
  return out;
}

function crypto_curve_to_hidden(curve, tweak) {
  assertReady();
  const ptr = wasm._malloc(KEY_BYTES * 2);
  if (curve) wasm.HEAPU8.set(curve, ptr + KEY_BYTES, KEY_BYTES);
  const success = wasm._crypto_curve_to_hidden(ptr, curve && (ptr + KEY_BYTES), tweak) === 0;
  const out = success ? wasm.HEAPU8.slice(ptr, ptr + KEY_BYTES) : null;
  wasm._crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
  wasm._free(ptr);
  return out;
}
function crypto_hidden_to_curve(hidden) {
  assertReady();
  const ptr = wasm._malloc(KEY_BYTES * 2);
  if (hidden) wasm.HEAPU8.set(hidden, ptr + KEY_BYTES, KEY_BYTES);
  wasm._crypto_hidden_to_curve(ptr, hidden && (ptr + KEY_BYTES));
  const out = wasm.HEAPU8.slice(ptr, ptr + KEY_BYTES);
  wasm._crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
  wasm._free(ptr);
  return out;
}
function crypto_hidden_key_pair(seed) {
  assertReady();
  const ptr = wasm._malloc(KEY_BYTES * 3);
  if (seed) wasm.HEAPU8.set(seed, ptr + KEY_BYTES * 2, KEY_BYTES);
  wasm._crypto_hidden_key_pair(ptr, ptr + KEY_BYTES, seed && (ptr + KEY_BYTES * 2));
  const hidden = wasm.HEAPU8.slice(ptr, ptr + KEY_BYTES);
  const secret_key = wasm.HEAPU8.slice(ptr + KEY_BYTES, ptr + KEY_BYTES * 2);
  wasm._crypto_wipe(ptr, KEY_BYTES * 3);
  wasm._free(ptr);
  return { hidden, secret_key };
}

function crypto_from_eddsa_private(eddsa) {
  assertReady();
  const ptr = wasm._malloc(KEY_BYTES * 2);
  if (eddsa) wasm.HEAPU8.set(eddsa, ptr + KEY_BYTES, KEY_BYTES);
  wasm._crypto_from_eddsa_private(ptr, eddsa && (ptr + KEY_BYTES));
  const out = wasm.HEAPU8.slice(ptr, ptr + KEY_BYTES);
  wasm._crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
  wasm._free(ptr);
  return out;
}
function crypto_from_eddsa_public(eddsa) {
  assertReady();
  const ptr = wasm._malloc(KEY_BYTES * 2);
  if (eddsa) wasm.HEAPU8.set(eddsa, ptr + KEY_BYTES, KEY_BYTES);
  wasm._crypto_from_eddsa_public(ptr, eddsa && (ptr + KEY_BYTES));
  const out = wasm.HEAPU8.slice(ptr, ptr + KEY_BYTES);
  wasm._free(ptr);
  return out;
}

function crypto_hchacha20(key, in_) {
  assertReady();
  const ptr = wasm._malloc(KEY_BYTES * 2 + 16);
  if (key) wasm.HEAPU8.set(key, ptr + KEY_BYTES, KEY_BYTES);
  if (in_) wasm.HEAPU8.set(in_, ptr + KEY_BYTES * 2, 16);
  wasm._crypto_hchacha20(ptr, key && (ptr + KEY_BYTES), in_ && (ptr + KEY_BYTES * 2));
  const out = wasm.HEAPU8.slice(ptr, ptr + KEY_BYTES);
  wasm._crypto_wipe(ptr + KEY_BYTES, KEY_BYTES + 16);
  wasm._free(ptr);
  return out;
}

function crypto_ietf_chacha20(plain_text, key, nonce) {
  assertReady();
  const textLength = plain_text ? plain_text.byteLength : 0;
  const ptr = wasm._malloc(textLength + KEY_BYTES + 12);
  if (plain_text) wasm.HEAPU8.set(plain_text, ptr);
  if (key) wasm.HEAPU8.set(key, ptr + textLength, KEY_BYTES);
  if (nonce) wasm.HEAPU8.set(nonce, ptr + textLength + KEY_BYTES, 12);
  wasm._crypto_ietf_chacha20(
    ptr, ptr, textLength,
    key && (ptr + textLength),
    nonce && (ptr + textLength + KEY_BYTES)
  );
  const out = wasm.HEAPU8.slice(ptr, ptr + textLength);
  wasm._crypto_wipe(ptr + textLength, KEY_BYTES);
  wasm._free(ptr);
  return out;
}

function crypto_key_exchange(your_secret_key, their_public_key) {
  assertReady();
  const ptr = wasm._malloc(KEY_BYTES * 3);
  if (your_secret_key) wasm.HEAPU8.set(your_secret_key, ptr + KEY_BYTES, KEY_BYTES)
  if (their_public_key) wasm.HEAPU8.set(their_public_key, ptr + KEY_BYTES * 2, KEY_BYTES)
  wasm._crypto_key_exchange(
    ptr,
    your_secret_key && (ptr + KEY_BYTES),
    their_public_key && (ptr + KEY_BYTES * 2)
  );
  const out = wasm.HEAPU8.slice(ptr, ptr + KEY_BYTES);
  wasm._free(ptr);
  return out;
}
function crypto_key_exchange_public_key(your_secret_key) {
  return crypto_sign_public_key(your_secret_key);
}

function crypto_lock(key, nonce, plain_text) {
  assertReady();
  const textLength = plain_text ? plain_text.byteLength : 0;
  const ptr = wasm._malloc(MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES);
  if (plain_text) wasm.HEAPU8.set(plain_text, ptr + MAC_BYTES);
  if (key) wasm.HEAPU8.set(key, ptr + MAC_BYTES + textLength);
  if (nonce) wasm.HEAPU8.set(nonce, ptr + MAC_BYTES + textLength + KEY_BYTES);
  wasm._crypto_lock(
    ptr,
    ptr + MAC_BYTES,
    key && (ptr + MAC_BYTES + textLength),
    nonce && (ptr + MAC_BYTES + textLength + KEY_BYTES),
    ptr + MAC_BYTES, textLength
  );
  const out = wasm.HEAPU8.slice(ptr, ptr + MAC_BYTES + textLength);
  wasm._crypto_wipe(ptr + MAC_BYTES + textLength, KEY_BYTES);
  wasm._free(ptr);
  return out;
}
function crypto_unlock(key, nonce, cipher_text) {
  assertReady();
  const textLength = cipher_text.byteLength - MAC_BYTES;
  const ptr = wasm._malloc(MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES);
  wasm.HEAPU8.set(cipher_text, ptr);
  if (key) wasm.HEAPU8.set(key, ptr + MAC_BYTES + textLength);
  if (nonce) wasm.HEAPU8.set(nonce, ptr + MAC_BYTES + textLength + KEY_BYTES);
  const success = wasm._crypto_unlock(
    ptr + MAC_BYTES,
    key && (ptr + MAC_BYTES + textLength),
    nonce && (ptr + MAC_BYTES + textLength + KEY_BYTES),
    ptr,
    ptr + MAC_BYTES, textLength
  ) === 0;
  const out = success ? wasm.HEAPU8.slice(ptr, ptr + MAC_BYTES + textLength) : null;
  wasm._crypto_wipe(ptr + MAC_BYTES + textLength, KEY_BYTES);
  wasm._free(ptr);
  return out;
}
function crypto_lock_aead(key, nonce, ad, plain_text) {
  assertReady();
  const textLength = plain_text ? plain_text.byteLength : 0;
  const adLength = ad ? ad.byteLength : 0;
  const ptr = wasm._malloc(MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES + adLength);
  if (plain_text) wasm.HEAPU8.set(plain_text, ptr + MAC_BYTES);
  if (key) wasm.HEAPU8.set(key, ptr + MAC_BYTES + textLength);
  if (nonce) wasm.HEAPU8.set(nonce, ptr + MAC_BYTES + textLength + KEY_BYTES);
  if (ad) wasm.HEAPU8.set(ad, ptr + MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES);
  wasm._crypto_lock_aead(
    ptr,
    ptr + MAC_BYTES,
    key && (ptr + MAC_BYTES + textLength),
    nonce && (ptr + MAC_BYTES + textLength + KEY_BYTES),
    ad && (ptr + MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES), adLength,
    ptr + MAC_BYTES, textLength
  );
  const out = wasm.HEAPU8.slice(ptr, ptr + MAC_BYTES + textLength);
  wasm._crypto_wipe(ptr + MAC_BYTES + textLength, KEY_BYTES);
  wasm._free(ptr);
  return out;
}
function crypto_unlock_aead(key, nonce, ad, cipher_text) {
  assertReady();
  const textLength = cipher_text.byteLength - MAC_BYTES;
  const adLength = ad ? ad.byteLength : 0;
  const ptr = wasm._malloc(MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES + adLength);
  wasm.HEAPU8.set(cipher_text, ptr);
  if (key) wasm.HEAPU8.set(key, ptr + MAC_BYTES + textLength);
  if (nonce) wasm.HEAPU8.set(nonce, ptr + MAC_BYTES + textLength + KEY_BYTES);
  if (ad) wasm.HEAPU8.set(ad, ptr + MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES);
  const success = wasm._crypto_unlock_aead(
    ptr + MAC_BYTES,
    key && (ptr + MAC_BYTES + textLength),
    nonce && (ptr + MAC_BYTES + textLength + KEY_BYTES),
    ptr,
    ad && (ptr + MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES), adLength,
    ptr + MAC_BYTES, textLength
  ) === 0;
  const out = success ? wasm.HEAPU8.slice(ptr, ptr + MAC_BYTES + textLength) : null;
  wasm._crypto_wipe(ptr + MAC_BYTES + textLength, KEY_BYTES);
  wasm._free(ptr);
  return out;
}

function crypto_poly1305(message, key) {
  assertReady();
  const messageLength = message ? message.byteLength : 0;
  const ptr = wasm._malloc(MAC_BYTES + KEY_BYTES + messageLength);
  wasm.HEAPU8.set(key, ptr + MAC_BYTES, KEY_BYTES);
  if (message) wasm.HEAPU8.set(message, ptr + MAC_BYTES + KEY_BYTES);
  wasm._crypto_poly1305(ptr, ptr + MAC_BYTES + KEY_BYTES, messageLength, ptr + MAC_BYTES);
  const out = wasm.HEAPU8.slice(ptr, ptr + MAC_BYTES);
  wasm._free(ptr);
  return out;
}

function crypto_sign_public_key(secret_key) {
  assertReady();
  const ptr = wasm._malloc(KEY_BYTES * 2);
  if (secret_key) wasm.HEAPU8.set(secret_key, ptr + KEY_BYTES, KEY_BYTES);
  wasm._crypto_sign_public_key(ptr, secret_key && (ptr + KEY_BYTES));
  const out = wasm.HEAPU8.slice(ptr, secret_key && (ptr + KEY_BYTES));
  wasm._crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
  wasm._free(ptr);
  return out;
}
function crypto_sign(secret_key, public_key, message) {
  assertReady();
  const messageLength = message ? message.byteLength : 0;
  const ptr = wasm._malloc(HASH_BYTES + KEY_BYTES + KEY_BYTES + messageLength);
  if (secret_key) wasm.HEAPU8.set(secret_key, ptr + HASH_BYTES, KEY_BYTES);
  if (public_key) wasm.HEAPU8.set(public_key, ptr + HASH_BYTES + KEY_BYTES, KEY_BYTES);
  if (message) wasm.HEAPU8.set(message, ptr + HASH_BYTES + KEY_BYTES * 2);
  wasm._crypto_sign(
    ptr,
    secret_key && (ptr + HASH_BYTES),
    public_key && (ptr + HASH_BYTES + KEY_BYTES),
    message && (ptr + HASH_BYTES + KEY_BYTES * 2), messageLength
  );
  const out = wasm.HEAPU8.slice(ptr, ptr + HASH_BYTES);
  wasm._crypto_wipe(ptr + HASH_BYTES + KEY_BYTES, KEY_BYTES);
  wasm._free(ptr);
  return out;
}
function crypto_check(signature, public_key, message) {
  assertReady();
  const messageLength = message ? message.byteLength : 0;
  const ptr = wasm._malloc(HASH_BYTES + KEY_BYTES + messageLength);
  if (signature) wasm.HEAPU8.set(signature, ptr, HASH_BYTES);
  if (public_key) wasm.HEAPU8.set(public_key, ptr + HASH_BYTES, KEY_BYTES);
  if (message) wasm.HEAPU8.set(message, ptr + HASH_BYTES + KEY_BYTES);
  const out = wasm._crypto_check(
    signature && ptr,
    public_key && (ptr + HASH_BYTES),
    message && (ptr + HASH_BYTES + KEY_BYTES), message.byteLength
  ) === 0;
  wasm._free(ptr);
  return out;
}

function crypto_verify16(a, b) {
  assertReady();
  const ptr = wasm._malloc(32);
  wasm.HEAPU8.set(a, ptr);
  wasm.HEAPU8.set(b, ptr + 16);
  const result = wasm._crypto_verify16(ptr, ptr + 16) === 0;
  wasm._free(ptr);
  return result;
}
function crypto_verify32(a, b) {
  assertReady();
  const ptr = wasm._malloc(64);
  wasm.HEAPU8.set(a, ptr);
  wasm.HEAPU8.set(b, ptr + 32);
  const result = wasm._crypto_verify32(ptr, ptr + 32) === 0;
  wasm._free(ptr);
  return result;
}
function crypto_verify64(a, b) {
  assertReady();
  const ptr = wasm._malloc(128);
  wasm.HEAPU8.set(a, ptr);
  wasm.HEAPU8.set(b, ptr + 64);
  const result = wasm._crypto_verify64(ptr, ptr + 64) === 0;
  wasm._free(ptr);
  return result;
}

function crypto_x25519(your_secret_key, their_public_key) {
  assertReady();
  const ptr = wasm._malloc(KEY_BYTES * 3);
  if (your_secret_key) wasm.HEAPU8.set(your_secret_key, ptr + KEY_BYTES, KEY_BYTES)
  if (their_public_key) wasm.HEAPU8.set(their_public_key, ptr + KEY_BYTES * 2, KEY_BYTES)
  wasm._crypto_x25519(
    ptr,
    your_secret_key && (ptr + KEY_BYTES),
    their_public_key && (ptr + KEY_BYTES * 2)
  );
  const out = wasm.HEAPU8.slice(ptr, ptr + KEY_BYTES);
  wasm._free(ptr);
  return out;
}
function crypto_x25519_public_key(secret_key) {
  assertReady();
  const ptr = wasm._malloc(KEY_BYTES * 2);
  if (secret_key) wasm.HEAPU8.set(secret_key, ptr + KEY_BYTES, KEY_BYTES);
  wasm._crypto_x25519_public_key(ptr, secret_key && (ptr + KEY_BYTES));
  const out = wasm.HEAPU8.slice(ptr, ptr + KEY_BYTES);
  wasm._crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
  wasm._free(ptr);
  return out;
}

function crypto_x25519_dirty_fast(secret_key) {
  assertReady();
  const ptr = wasm._malloc(KEY_BYTES * 2);
  if (secret_key) wasm.HEAPU8.set(secret_key, ptr + KEY_BYTES, KEY_BYTES);
  wasm._crypto_x25519_dirty_fast(ptr, secret_key && (ptr + KEY_BYTES));
  const out = wasm.HEAPU8.slice(ptr, ptr + KEY_BYTES);
  wasm._crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
  wasm._free(ptr);
  return out;
}
function crypto_x25519_dirty_small(secret_key) {
  assertReady();
  const ptr = wasm._malloc(KEY_BYTES * 2);
  if (secret_key) wasm.HEAPU8.set(secret_key, ptr + KEY_BYTES, KEY_BYTES);
  wasm._crypto_x25519_dirty_small(ptr, secret_key && (ptr + KEY_BYTES));
  const out = wasm.HEAPU8.slice(ptr, ptr + KEY_BYTES);
  wasm._crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
  wasm._free(ptr);
  return out;
}
function crypto_x25519_inverse(private_key, curve_point) {
  assertReady();
  const ptr = wasm._malloc(KEY_BYTES * 3);
  if (private_key) wasm.HEAPU8.set(private_key, ptr + KEY_BYTES, KEY_BYTES);
  if (curve_point) wasm.HEAPU8.set(curve_point, ptr + KEY_BYTES * 2, KEY_BYTES);
  wasm._crypto_x25519_inverse(ptr, private_key && (ptr + KEY_BYTES), curve_point && (ptr + KEY_BYTES * 2));
  const out = wasm.HEAPU8.slice(ptr, ptr + KEY_BYTES);
  wasm._crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
  wasm._free(ptr);
  return out;
}

module.exports = {
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
  MAC_BYTES,
  NONCE_BYTES,
  CHACHA20_NONCE_BYTES
}
