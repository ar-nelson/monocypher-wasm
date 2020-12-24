const loadMonocypher = require('./monocypher');
const MODULE = Symbol('MODULE');
const ARGON2I_WORK_AREA = Symbol('ARGON2I_WORK_AREA');
const ARGON2I_MAX_BLOCKS = Symbol('ARGON2I_MAX_BLOCKS');
const HASH_BYTES = 64;
const KEY_BYTES = 32;
const MAC_BYTES = 16;
const NONCE_BYTES = 24;
const CHACHA20_NONCE_BYTES = 8;

class MonocypherModule {
  constructor(mod) {
    this[MODULE] = mod;
    this[ARGON2I_MAX_BLOCKS] = 0;
  }

  crypto_argon2i(hash_size, nb_blocks, nb_iterations, password, salt) {
    if (nb_blocks < 8) {
      throw new Error("crypto_argon2i: nb_blocks must be at least 8");
    }
    const mod = this[MODULE];
    if (!this[ARGON2I_WORK_AREA] || nb_blocks > this[ARGON2I_MAX_BLOCKS]) {
      if (this[ARGON2I_WORK_AREA]) {
        mod._free(this[ARGON2I_WORK_AREA]);
      }
      this[ARGON2I_WORK_AREA] = mod._malloc(nb_blocks * 1024);
      this[ARGON2I_MAX_BLOCKS] = nb_blocks;
    }
    const passwordLength = password ? password.byteLength : 0;
    const saltLength = salt ? salt.byteLength : 0;
    const ptr = mod._malloc(hash_size + passwordLength + saltLength);
    if (password) mod.HEAPU8.set(password, ptr + hash_size);
    if (salt) mod.HEAPU8.set(salt, ptr + hash_size + passwordLength);
    mod._crypto_argon2i(
      ptr, hash_size,
      this[ARGON2I_WORK_AREA], nb_blocks, nb_iterations,
      password && (ptr + hash_size), passwordLength,
      salt && (ptr + hash_size + passwordLength), saltLength
    );
    const out = mod.HEAPU8.slice(ptr, ptr + hash_size);
    mod._free(ptr);
    return out;
  }
  crypto_argon2i_general(hash_size, nb_blocks, nb_iterations, password, salt, key, ad) {
    if (nb_blocks < 8) {
      throw new Error("crypto_argon2i: nb_blocks must be at least 8");
    }
    const mod = this[MODULE];
    if (!this[ARGON2I_WORK_AREA] || nb_blocks > this[ARGON2I_MAX_BLOCKS]) {
      if (this[ARGON2I_WORK_AREA]) {
        mod._free(this[ARGON2I_WORK_AREA]);
      }
      this[ARGON2I_WORK_AREA] = mod._malloc(nb_blocks * 1024);
      this[ARGON2I_MAX_BLOCKS] = nb_blocks;
    }
    const passwordLength = password ? password.byteLength : 0;
    const saltLength = salt ? salt.byteLength : 0;
    const keyLength = key ? key.byteLength : 0;
    const adLength = ad ? ad.byteLength : 0;
    const ptr = mod._malloc(hash_size + passwordLength + saltLength + keyLength + adLength);
    if (password) mod.HEAPU8.set(password, ptr + hash_size);
    if (salt) mod.HEAPU8.set(salt, ptr + hash_size + passwordLength);
    if (key) mod.HEAPU8.set(key, ptr + hash_size + passwordLength + saltLength);
    if (ad) mod.HEAPU8.set(ad, ptr + hash_size + passwordLength + saltLength + keyLength);
    mod._crypto_argon2i_general(
      ptr, hash_size,
      this[ARGON2I_WORK_AREA], nb_blocks, nb_iterations,
      password && (ptr + hash_size), passwordLength,
      salt && (ptr + hash_size + passwordLength), saltLength,
      key && (ptr + hash_size + passwordLength + saltLength), keyLength,
      ad && (ptr + hash_size + passwordLength + saltLength + keyLength), adLength
    );
    const out = mod.HEAPU8.slice(ptr, ptr + hash_size);
    mod._free(ptr);
    return out;
  }

  crypto_blake2b(message) {
    const mod = this[MODULE];
    const messageLength = message ? message.byteLength : 0;
    const ptr = mod._malloc(HASH_BYTES + messageLength);
    if (message) mod.HEAPU8.set(message, ptr + HASH_BYTES);
    mod._crypto_blake2b(ptr, message && (ptr + HASH_BYTES), messageLength);
    const out = mod.HEAPU8.slice(ptr, ptr + HASH_BYTES);
    mod._free(ptr);
    return out;
  }
  crypto_blake2b_general(hash_size, key, message) {
    const mod = this[MODULE];
    const keyLength = key ? key.byteLength : 0;
    const messageLength = message ? message.byteLength : 0;
    const ptr = mod._malloc(hash_size + keyLength + messageLength);
    if (key) mod.HEAPU8.set(key, ptr + hash_size);
    if (message) mod.HEAPU8.set(message, ptr + hash_size + keyLength);
    mod._crypto_blake2b_general(
      ptr, hash_size,
      key && (ptr + hash_size), keyLength,
      message && (ptr + hash_size + keyLength), messageLength
    );
    const out = mod.HEAPU8.slice(ptr, ptr + hash_size);
    mod._free(ptr);
    return out;
  }

  crypto_chacha20(plain_text, key, nonce) {
    const mod = this[MODULE];
    const textLength = plain_text ? plain_text.byteLength : 0;
    const ptr = mod._malloc(textLength + KEY_BYTES + CHACHA20_NONCE_BYTES);
    if (plain_text) mod.HEAPU8.set(plain_text, ptr);
    if (key) mod.HEAPU8.set(key, ptr + textLength, KEY_BYTES);
    if (nonce) mod.HEAPU8.set(nonce, ptr + textLength + KEY_BYTES, CHACHA20_NONCE_BYTES);
    mod._crypto_chacha20(
      ptr, ptr, textLength,
      key && (ptr + textLength),
      nonce && (ptr + textLength + KEY_BYTES)
    );
    const out = mod.HEAPU8.slice(ptr, ptr + textLength);
    mod._crypto_wipe(ptr + textLength, KEY_BYTES);
    mod._free(ptr);
    return out;
  }
  crypto_xchacha20(plain_text, key, nonce) {
    const mod = this[MODULE];
    const textLength = plain_text ? plain_text.byteLength : 0;
    const ptr = mod._malloc(textLength + KEY_BYTES + NONCE_BYTES);
    if (plain_text) mod.HEAPU8.set(plain_text, ptr);
    if (key) mod.HEAPU8.set(key, ptr + textLength, KEY_BYTES);
    if (nonce) mod.HEAPU8.set(nonce, ptr + textLength + KEY_BYTES, NONCE_BYTES);
    mod._crypto_xchacha20(
      ptr, ptr, textLength,
      key && (ptr + textLength),
      nonce && (ptr + textLength + KEY_BYTES)
    );
    const out = mod.HEAPU8.slice(ptr, ptr + textLength);
    mod._crypto_wipe(ptr + textLength, KEY_BYTES);
    mod._free(ptr);
    return out;
  }

  crypto_curve_to_hidden(curve, tweak) {
    const mod = this[MODULE];
    const ptr = mod._malloc(KEY_BYTES * 2);
    if (curve) mod.HEAPU8.set(curve, ptr + KEY_BYTES, KEY_BYTES);
    const success = mod._crypto_curve_to_hidden(ptr, curve && (ptr + KEY_BYTES), tweak) === 0;
    const out = success ? mod.HEAPU8.slice(ptr, ptr + KEY_BYTES) : null;
    mod._crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
    mod._free(ptr);
    return out;
  }
  crypto_hidden_to_curve(hidden) {
    const mod = this[MODULE];
    const ptr = mod._malloc(KEY_BYTES * 2);
    if (hidden) mod.HEAPU8.set(hidden, ptr + KEY_BYTES, KEY_BYTES);
    mod._crypto_hidden_to_curve(ptr, hidden && (ptr + KEY_BYTES));
    const out = mod.HEAPU8.slice(ptr, ptr + KEY_BYTES);
    mod._crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
    mod._free(ptr);
    return out;
  }
  crypto_hidden_key_pair(seed) {
    const mod = this[MODULE];
    const ptr = mod._malloc(KEY_BYTES * 3);
    if (seed) mod.HEAPU8.set(seed, ptr + KEY_BYTES * 2, KEY_BYTES);
    mod._crypto_hidden_key_pair(ptr, ptr + KEY_BYTES, seed && (ptr + KEY_BYTES * 2));
    const hidden = mod.HEAPU8.slice(ptr, ptr + KEY_BYTES);
    const secret_key = mod.HEAPU8.slice(ptr + KEY_BYTES, ptr + KEY_BYTES * 2);
    mod._crypto_wipe(ptr, KEY_BYTES * 3);
    mod._free(ptr);
    return { hidden, secret_key };
  }

  crypto_from_eddsa_private(eddsa) {
    const mod = this[MODULE];
    const ptr = mod._malloc(KEY_BYTES * 2);
    if (eddsa) mod.HEAPU8.set(eddsa, ptr + KEY_BYTES, KEY_BYTES);
    mod._crypto_from_eddsa_private(ptr, eddsa && (ptr + KEY_BYTES));
    const out = mod.HEAPU8.slice(ptr, ptr + KEY_BYTES);
    mod._crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
    mod._free(ptr);
    return out;
  }
  crypto_from_eddsa_public(eddsa) {
    const mod = this[MODULE];
    const ptr = mod._malloc(KEY_BYTES * 2);
    if (eddsa) mod.HEAPU8.set(eddsa, ptr + KEY_BYTES, KEY_BYTES);
    mod._crypto_from_eddsa_public(ptr, eddsa && (ptr + KEY_BYTES));
    const out = mod.HEAPU8.slice(ptr, ptr + KEY_BYTES);
    mod._free(ptr);
    return out;
  }

  crypto_hchacha20(key, in_) {
    const mod = this[MODULE];
    const ptr = mod._malloc(KEY_BYTES * 2 + 16);
    if (key) mod.HEAPU8.set(key, ptr + KEY_BYTES, KEY_BYTES);
    if (in_) mod.HEAPU8.set(in_, ptr + KEY_BYTES * 2, 16);
    mod._crypto_hchacha20(ptr, key && (ptr + KEY_BYTES), in_ && (ptr + KEY_BYTES * 2));
    const out = mod.HEAPU8.slice(ptr, ptr + KEY_BYTES);
    mod._crypto_wipe(ptr + KEY_BYTES, KEY_BYTES + 16);
    mod._free(ptr);
    return out;
  }

  crypto_ietf_chacha20(plain_text, key, nonce) {
    const mod = this[MODULE];
    const textLength = plain_text ? plain_text.byteLength : 0;
    const ptr = mod._malloc(textLength + KEY_BYTES + 12);
    if (plain_text) mod.HEAPU8.set(plain_text, ptr);
    if (key) mod.HEAPU8.set(key, ptr + textLength, KEY_BYTES);
    if (nonce) mod.HEAPU8.set(nonce, ptr + textLength + KEY_BYTES, 12);
    mod._crypto_ietf_chacha20(
      ptr, ptr, textLength,
      key && (ptr + textLength),
      nonce && (ptr + textLength + KEY_BYTES)
    );
    const out = mod.HEAPU8.slice(ptr, ptr + textLength);
    mod._crypto_wipe(ptr + textLength, KEY_BYTES);
    mod._free(ptr);
    return out;
  }

  crypto_key_exchange(your_secret_key, their_public_key) {
    const mod = this[MODULE];
    const ptr = mod._malloc(KEY_BYTES * 3);
    if (your_secret_key) mod.HEAPU8.set(your_secret_key, ptr + KEY_BYTES, KEY_BYTES)
    if (their_public_key) mod.HEAPU8.set(their_public_key, ptr + KEY_BYTES * 2, KEY_BYTES)
    mod._crypto_key_exchange(
      ptr,
      your_secret_key && (ptr + KEY_BYTES),
      their_public_key && (ptr + KEY_BYTES * 2)
    );
    const out = mod.HEAPU8.slice(ptr, ptr + KEY_BYTES);
    mod._free(ptr);
    return out;
  }
  crypto_key_exchange_public_key(your_secret_key) {
    return this.crypto_sign_public_key(your_secret_key);
  }

  crypto_lock(key, nonce, plain_text) {
    const mod = this[MODULE];
    const textLength = plain_text ? plain_text.byteLength : 0;
    const ptr = mod._malloc(MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES);
    if (plain_text) mod.HEAPU8.set(plain_text, ptr + MAC_BYTES);
    if (key) mod.HEAPU8.set(key, ptr + MAC_BYTES + textLength);
    if (nonce) mod.HEAPU8.set(nonce, ptr + MAC_BYTES + textLength + KEY_BYTES);
    mod._crypto_lock(
      ptr,
      ptr + MAC_BYTES,
      key && (ptr + MAC_BYTES + textLength),
      nonce && (ptr + MAC_BYTES + textLength + KEY_BYTES),
      ptr + MAC_BYTES, textLength
    );
    const out = mod.HEAPU8.slice(ptr, ptr + MAC_BYTES + textLength);
    mod._crypto_wipe(ptr + MAC_BYTES + textLength, KEY_BYTES);
    mod._free(ptr);
    return out;
  }
  crypto_unlock(key, nonce, cipher_text) {
    const mod = this[MODULE];
    const textLength = cipher_text.byteLength - MAC_BYTES;
    const ptr = mod._malloc(MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES);
    mod.HEAPU8.set(cipher_text, ptr);
    if (key) mod.HEAPU8.set(key, ptr + MAC_BYTES + textLength);
    if (nonce) mod.HEAPU8.set(nonce, ptr + MAC_BYTES + textLength + KEY_BYTES);
    const success = mod._crypto_unlock(
      ptr + MAC_BYTES,
      key && (ptr + MAC_BYTES + textLength),
      nonce && (ptr + MAC_BYTES + textLength + KEY_BYTES),
      ptr,
      ptr + MAC_BYTES, textLength
    ) === 0;
    const out = success ? mod.HEAPU8.slice(ptr, ptr + MAC_BYTES + textLength) : null;
    mod._crypto_wipe(ptr + MAC_BYTES + textLength, KEY_BYTES);
    mod._free(ptr);
    return out;
  }
  crypto_lock_aead(key, nonce, ad, plain_text) {
    const mod = this[MODULE];
    const textLength = plain_text ? plain_text.byteLength : 0;
    const adLength = ad ? ad.byteLength : 0;
    const ptr = mod._malloc(MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES + adLength);
    if (plain_text) mod.HEAPU8.set(plain_text, ptr + MAC_BYTES);
    if (key) mod.HEAPU8.set(key, ptr + MAC_BYTES + textLength);
    if (nonce) mod.HEAPU8.set(nonce, ptr + MAC_BYTES + textLength + KEY_BYTES);
    if (ad) mod.HEAPU8.set(ad, ptr + MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES);
    mod._crypto_lock_aead(
      ptr,
      ptr + MAC_BYTES,
      key && (ptr + MAC_BYTES + textLength),
      nonce && (ptr + MAC_BYTES + textLength + KEY_BYTES),
      ad && (ptr + MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES), adLength,
      ptr + MAC_BYTES, textLength
    );
    const out = mod.HEAPU8.slice(ptr, ptr + MAC_BYTES + textLength);
    mod._crypto_wipe(ptr + MAC_BYTES + textLength, KEY_BYTES);
    mod._free(ptr);
    return out;
  }
  crypto_unlock_aead(key, nonce, ad, cipher_text) {
    const mod = this[MODULE];
    const textLength = cipher_text.byteLength - MAC_BYTES;
    const adLength = ad ? ad.byteLength : 0;
    const ptr = mod._malloc(MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES + adLength);
    mod.HEAPU8.set(cipher_text, ptr);
    if (key) mod.HEAPU8.set(key, ptr + MAC_BYTES + textLength);
    if (nonce) mod.HEAPU8.set(nonce, ptr + MAC_BYTES + textLength + KEY_BYTES);
    if (ad) mod.HEAPU8.set(ad, ptr + MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES);
    const success = mod._crypto_unlock_aead(
      ptr + MAC_BYTES,
      key && (ptr + MAC_BYTES + textLength),
      nonce && (ptr + MAC_BYTES + textLength + KEY_BYTES),
      ptr,
      ad && (ptr + MAC_BYTES + textLength + KEY_BYTES + NONCE_BYTES), adLength,
      ptr + MAC_BYTES, textLength
    ) === 0;
    const out = success ? mod.HEAPU8.slice(ptr, ptr + MAC_BYTES + textLength) : null;
    mod._crypto_wipe(ptr + MAC_BYTES + textLength, KEY_BYTES);
    mod._free(ptr);
    return out;
  }

  crypto_poly1305(message, key) {
    const mod = this[MODULE];
    const messageLength = message ? message.byteLength : 0;
    const ptr = mod._malloc(MAC_BYTES + KEY_BYTES + messageLength);
    mod.HEAPU8.set(key, ptr + MAC_BYTES, KEY_BYTES);
    if (message) mod.HEAPU8.set(message, ptr + MAC_BYTES + KEY_BYTES);
    mod._crypto_poly1305(ptr, ptr + MAC_BYTES + KEY_BYTES, messageLength, ptr + MAC_BYTES);
    const out = mod.HEAPU8.slice(ptr, ptr + MAC_BYTES);
    mod._free(ptr);
    return out;
  }

  crypto_sign_public_key(secret_key) {
    const mod = this[MODULE];
    const ptr = mod._malloc(KEY_BYTES * 2);
    if (secret_key) mod.HEAPU8.set(secret_key, ptr + KEY_BYTES, KEY_BYTES);
    mod._crypto_sign_public_key(ptr, secret_key && (ptr + KEY_BYTES));
    const out = mod.HEAPU8.slice(ptr, secret_key && (ptr + KEY_BYTES));
    mod._crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
    mod._free(ptr);
    return out;
  }
  crypto_sign(secret_key, public_key, message) {
    const mod = this[MODULE];
    const messageLength = message ? message.byteLength : 0;
    const ptr = mod._malloc(HASH_BYTES + KEY_BYTES + KEY_BYTES + messageLength);
    if (secret_key) mod.HEAPU8.set(secret_key, ptr + HASH_BYTES, KEY_BYTES);
    if (public_key) mod.HEAPU8.set(public_key, ptr + HASH_BYTES + KEY_BYTES, KEY_BYTES);
    if (message) mod.HEAPU8.set(message, ptr + HASH_BYTES + KEY_BYTES * 2);
    mod._crypto_sign(
      ptr,
      secret_key && (ptr + HASH_BYTES),
      public_key && (ptr + HASH_BYTES + KEY_BYTES),
      message && (ptr + HASH_BYTES + KEY_BYTES * 2), messageLength
    );
    const out = mod.HEAPU8.slice(ptr, ptr + HASH_BYTES);
    mod._crypto_wipe(ptr + HASH_BYTES + KEY_BYTES, KEY_BYTES);
    mod._free(ptr);
    return out;
  }
  crypto_check(signature, public_key, message) {
    const mod = this[MODULE];
    const messageLength = message ? message.byteLength : 0;
    const ptr = mod._malloc(HASH_BYTES + KEY_BYTES + messageLength);
    if (signature) mod.HEAPU8.set(signature, ptr, HASH_BYTES);
    if (public_key) mod.HEAPU8.set(public_key, ptr + HASH_BYTES, KEY_BYTES);
    if (message) mod.HEAPU8.set(message, ptr + HASH_BYTES + KEY_BYTES);
    const out = mod._crypto_check(
      signature && ptr,
      public_key && (ptr + HASH_BYTES),
      message && (ptr + HASH_BYTES + KEY_BYTES), message.byteLength
    ) === 0;
    mod._free(ptr);
    return out;
  }

  crypto_verify16(a, b) {
    const mod = this[MODULE];
    const ptr = mod._malloc(32);
    mod.HEAPU8.set(a, ptr);
    mod.HEAPU8.set(b, ptr + 16);
    const result = mod._crypto_verify16(ptr, ptr + 16) === 0;
    mod._free(ptr);
    return result;
  }
  crypto_verify32(a, b) {
    const mod = this[MODULE];
    const ptr = mod._malloc(64);
    mod.HEAPU8.set(a, ptr);
    mod.HEAPU8.set(b, ptr + 32);
    const result = mod._crypto_verify32(ptr, ptr + 32) === 0;
    mod._free(ptr);
    return result;
  }
  crypto_verify64(a, b) {
    const mod = this[MODULE];
    const ptr = mod._malloc(128);
    mod.HEAPU8.set(a, ptr);
    mod.HEAPU8.set(b, ptr + 64);
    const result = mod._crypto_verify64(ptr, ptr + 64) === 0;
    mod._free(ptr);
    return result;
  }

  crypto_x25519(your_secret_key, their_public_key) {
    const mod = this[MODULE];
    const ptr = mod._malloc(KEY_BYTES * 3);
    if (your_secret_key) mod.HEAPU8.set(your_secret_key, ptr + KEY_BYTES, KEY_BYTES)
    if (their_public_key) mod.HEAPU8.set(their_public_key, ptr + KEY_BYTES * 2, KEY_BYTES)
    mod._crypto_x25519(
      ptr,
      your_secret_key && (ptr + KEY_BYTES),
      their_public_key && (ptr + KEY_BYTES * 2)
    );
    const out = mod.HEAPU8.slice(ptr, ptr + KEY_BYTES);
    mod._free(ptr);
    return out;
  }
  crypto_x25519_public_key(secret_key) {
    const mod = this[MODULE];
    const ptr = mod._malloc(KEY_BYTES * 2);
    if (secret_key) mod.HEAPU8.set(secret_key, ptr + KEY_BYTES, KEY_BYTES);
    mod._crypto_x25519_public_key(ptr, secret_key && (ptr + KEY_BYTES));
    const out = mod.HEAPU8.slice(ptr, ptr + KEY_BYTES);
    mod._crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
    mod._free(ptr);
    return out;
  }

  crypto_x25519_dirty_fast(secret_key) {
    const mod = this[MODULE];
    const ptr = mod._malloc(KEY_BYTES * 2);
    if (secret_key) mod.HEAPU8.set(secret_key, ptr + KEY_BYTES, KEY_BYTES);
    mod._crypto_x25519_dirty_fast(ptr, secret_key && (ptr + KEY_BYTES));
    const out = mod.HEAPU8.slice(ptr, ptr + KEY_BYTES);
    mod._crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
    mod._free(ptr);
    return out;
  }
  crypto_x25519_dirty_small(secret_key) {
    const mod = this[MODULE];
    const ptr = mod._malloc(KEY_BYTES * 2);
    if (secret_key) mod.HEAPU8.set(secret_key, ptr + KEY_BYTES, KEY_BYTES);
    mod._crypto_x25519_dirty_small(ptr, secret_key && (ptr + KEY_BYTES));
    const out = mod.HEAPU8.slice(ptr, ptr + KEY_BYTES);
    mod._crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
    mod._free(ptr);
    return out;
  }
  crypto_x25519_inverse(private_key, curve_point) {
    const mod = this[MODULE];
    const ptr = mod._malloc(KEY_BYTES * 3);
    if (private_key) mod.HEAPU8.set(private_key, ptr + KEY_BYTES, KEY_BYTES);
    if (curve_point) mod.HEAPU8.set(curve_point, ptr + KEY_BYTES * 2, KEY_BYTES);
    mod._crypto_x25519_inverse(ptr, private_key && (ptr + KEY_BYTES), curve_point && (ptr + KEY_BYTES * 2));
    const out = mod.HEAPU8.slice(ptr, ptr + KEY_BYTES);
    mod._crypto_wipe(ptr + KEY_BYTES, KEY_BYTES);
    mod._free(ptr);
    return out;
  }
}

const Monocypher = loadMonocypher().then((mod) => new MonocypherModule(mod));

module.exports = {
  Monocypher,
  HASH_BYTES,
  KEY_BYTES,
  MAC_BYTES,
  NONCE_BYTES,
  CHACHA20_NONCE_BYTES
}
