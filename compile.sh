#!/bin/sh
emcc ./monocypher.c -o monocypher.js -s ALLOW_MEMORY_GROWTH -s MODULARIZE -s EXPORTED_FUNCTIONS='["_malloc","_free","_crypto_argon2i","_crypto_argon2i_general","_crypto_blake2b","_crypto_blake2b_general","_crypto_chacha20","_crypto_xchacha20","_crypto_curve_to_hidden","_crypto_hidden_to_curve","_crypto_hidden_key_pair","_crypto_from_eddsa_private","_crypto_from_eddsa_public","_crypto_hchacha20","_crypto_ietf_chacha20","_crypto_key_exchange","_crypto_lock","_crypto_unlock","_crypto_lock_aead","_crypto_unlock_aead","_crypto_poly1305","_crypto_sign_public_key","_crypto_sign","_crypto_check","_crypto_verify16","_crypto_verify32","_crypto_verify64","_crypto_wipe","_crypto_x25519","_crypto_x25519_public_key","_crypto_x25519_dirty_fast","_crypto_x25519_dirty_small","_crypto_x25519_inverse"]'