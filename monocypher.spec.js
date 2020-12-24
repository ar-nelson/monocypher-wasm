const { expect } = require('chai');
const { randomBytes } = require('crypto');
const { readFileSync } = require('fs');
const { gunzipSync } = require('zlib');
const { Monocypher } = require('.');

const vectors = JSON.parse(gunzipSync(readFileSync(`${__dirname}/test-vectors.json.gz`)).toString('utf8'));

class VectorReader {
  constructor(vectors) {
    this.vectors = vectors;
    this.i = 0;
  }

  get done() {
    return this.i >= this.vectors.length;
  }

  next() {
    const vec = this.vectors[this.i++];
    return vec && Buffer.from(vec, 'hex');
  }
}

describe('Monocypher WASM Port', function () {

  ////////////////////////////
  /// Tests aginst vectors ///
  ////////////////////////////

  // chacha20 skipped because counter functions are not implemented
  
  // ietf_chacha20 skipped because counter functions are not implemented

  it("hchacha20", async function () {
    const mc = await Monocypher;
    const reader = new VectorReader(vectors.hchacha20);
    while (!reader.done) {
      const key   = reader.next();
      const nonce = reader.next();
      const out   = reader.next();
      expect(mc.crypto_hchacha20(key, nonce)).to.deep.equal(out)
    }
  });

  // xchacha20 skipped because counter functions are not implemented

  it("poly1305", async function () {
    const mc = await Monocypher;
    const reader = new VectorReader(vectors.poly1305);
    while (!reader.done) {
      const key = reader.next();
      const msg = reader.next();
      const out = reader.next();
      expect(mc.crypto_poly1305(msg, key)).to.deep.equal(out);
    }
  });

  it("aead_ietf", async function () {
    const mc = await Monocypher;
    const reader = new VectorReader(vectors.aead_ietf);
    while (!reader.done) {
      const key   = reader.next();
      const nonce = reader.next();
      const ad    = reader.next();
      const text  = reader.next();
      const out   = reader.next();
      expect(mc.crypto_lock_aead(key, nonce, ad, text)).to.deep.equal(out);
    }
  });

  it("blake2b", async function () {
    const mc = await Monocypher;
    const reader = new VectorReader(vectors.blake2b);
    while (!reader.done) {
      const msg = reader.next();
      const key = reader.next();
      const out = reader.next();
      expect(mc.crypto_blake2b_general(out.byteLength, key, msg)).to.deep.equal(out);
    }
  });

  it("argon2i", async function () {
    const mc = await Monocypher;
    const reader = new VectorReader(vectors.argon2i);
    while (!reader.done) {
      const nb_blocks     = reader.next().readIntLE(0, 6);
      const nb_iterations = reader.next().readIntLE(0, 6);
      const password      = reader.next();
      const salt          = reader.next();
      const key           = reader.next();
      const ad            = reader.next();
      const out           = reader.next();
      expect(mc.crypto_argon2i_general(out.byteLength, nb_blocks, nb_iterations, password, salt, key, ad)).to.deep.equal(out);
    }
  });

  it("x25519", async function () {
    const mc = await Monocypher;
    const reader = new VectorReader(vectors.x25519);
    while (!reader.done) {
      const scalar = reader.next();
      const point  = reader.next();
      const out    = reader.next();
      expect(mc.crypto_x25519(scalar, point)).to.deep.equal(out);
    }
  });

  it("x25519_pk", async function () {
    const mc = await Monocypher;
    const reader = new VectorReader(vectors.x25519_pk);
    while (!reader.done) {
      const in_ = reader.next();
      const out = reader.next();
      expect(mc.crypto_x25519_public_key(in_)).to.deep.equal(out);
    }
  });

  it("key_exchange", async function () {
    const mc = await Monocypher;
    const reader = new VectorReader(vectors.key_exchange);
    while (!reader.done) {
      const secret_key = reader.next();
      const public_key = reader.next();
      const out        = reader.next();
      expect(mc.crypto_key_exchange(secret_key, public_key)).to.deep.equal(out);
    }
  });

  it("edDSA", async function () {
    const mc = await Monocypher;
    const reader = new VectorReader(vectors.edDSA);
    while (!reader.done) {
      const secret_k = reader.next();
      const public_k = reader.next();
      const msg      = reader.next();
      const out      = reader.next();

      // Sign with cached public key, then by reconstructing the key
      expect(mc.crypto_sign(secret_k, public_k, msg)).to.deep.equal(out);
      expect(mc.crypto_sign(secret_k, null, msg)).to.deep.equal(out, "reconstructing public key yields different signature");
    }
  });

  it("edDSA_pk", async function () {
    const mc = await Monocypher;
    const reader = new VectorReader(vectors.edDSA_pk);
    while (!reader.done) {
      const in_ = reader.next();
      const out = reader.next();
      expect(mc.crypto_sign_public_key(in_)).to.deep.equal(out);
    }
  });

  it("test_x25519", async function() {
    const mc = await Monocypher;

    function iterate_x25519(k, u) {
      const tmp = mc.crypto_x25519(k, u);
      u.set(k);
      k.set(tmp);
    }

    const _1 = Uint8Array.of(
      0x42, 0x2c, 0x8e, 0x7a, 0x62, 0x27, 0xd7, 0xbc,
      0xa1, 0x35, 0x0b, 0x3e, 0x2b, 0xb7, 0x27, 0x9f,
      0x78, 0x97, 0xb8, 0x7b, 0xb6, 0x85, 0x4b, 0x78,
      0x3c, 0x60, 0xe8, 0x03, 0x11, 0xae, 0x30, 0x79
    );
    const u = new Uint8Array(32);
    u[0] = 9;

    const k = mc.crypto_x25519_public_key(u);
    expect(k).to.deep.equal(_1);

    const _1k = Uint8Array.of(
      0x68, 0x4c, 0xf5, 0x9b, 0xa8, 0x33, 0x09, 0x55,
      0x28, 0x00, 0xef, 0x56, 0x6f, 0x2f, 0x4d, 0x3c,
      0x1c, 0x38, 0x87, 0xc4, 0x93, 0x60, 0xe3, 0x87,
      0x5f, 0x2e, 0xb9, 0x4d, 0x99, 0x53, 0x2c, 0x51
    );
    for (let i = 1; i < 1000; i++) {
      iterate_x25519(k, u);
    }
    expect(k).to.deep.equal(_1k);
  });

  it("elligator_dir", async function () {
    const mc = await Monocypher;
    const reader = new VectorReader(vectors.elligator_dir);
    while (!reader.done) {
      const in_ = reader.next();
      const out = reader.next();
      expect(mc.crypto_hidden_to_curve(in_)).to.deep.equal(out);
    }
  });

  it("elligator_inv", async function () {
    const mc = await Monocypher;
    const reader = new VectorReader(vectors.elligator_inv);
    while (!reader.done) {
      const point   = reader.next();
      const tweak   = reader.next()[0];
      const failure = !!reader.next()[0];
      const out     = reader.next();
      const result  = mc.crypto_curve_to_hidden(point, tweak);
      expect(!result).to.equal(failure, "Elligator inverse map: failure mismatch");
      if (result) {
        expect(result).to.deep.equal(out);
      }
    }
  });

  //////////////////////////////
  /// Self consistency tests ///
  //////////////////////////////
  
  function p_verify(size, compare) {
    const a = new Uint8Array(64); // size <= 64
    const b = new Uint8Array(64); // size <= 64
    for (let i = 0; i < 2; i++) {
      for (let j = 0; j < 2; j++) {
        // Set every byte to the chosen value, then compare
        for (let k = 0; k < size; k++) {
          a[k] = i;
          b[k] = j;
        }
        expect(compare(a, b)).to.equal(i == j);
        // Set only two bytes to the chosen value, then compare
        for (let k = 0; k < size / 2; k++) {
          for (let l = 0; l < size; l++) {
            a[l] = 0;
            b[l] = 0;
          }
          a[k] = i; a[k + size/2 - 1] = i;
          b[k] = j; b[k + size/2 - 1] = j;
          expect(compare(a, b)).to.equal(i == j);
        }
      }
    }
  }

  it("p_verify16", async function () {
    const mc = await Monocypher;
    p_verify(16, mc.crypto_verify16.bind(mc));
  });
  it("p_verify32", async function () {
    const mc = await Monocypher;
    p_verify(32, mc.crypto_verify32.bind(mc));
  });
  it("p_verify64", async function () {
    const mc = await Monocypher;
    p_verify(64, mc.crypto_verify64.bind(mc));
  });

  // p_chacha20_ctr skipped because counter functions are not implemented

  // p_chacha20_stream skipped because null pointers cannot be given a length

  // p_chacha20_same_ptr skipped because pointers are managed by wrapper

  // p_hchacha20 skipped because pointers are managed by wrapper

  // p_poly1305 skipped because incremental functions are not implemented

  // p_poly1305_overlap skipped because pointers are managed by wrapper

  // p_blake2b skipped becayse incremental functions are not implemented

  // p_blake2b_overlap skipped because pointers are managed by wrapper

  it("p_argon2i_easy", async function () {
    const mc = await Monocypher;
    const password = randomBytes(32);
    const salt = randomBytes(16);
    const hash_general = mc.crypto_argon2i_general(64, 8, 1, password, salt, null, null);
    const hash_easy = mc.crypto_argon2i(64, 8, 1, password, salt);
    expect(hash_general).to.deep.equal(hash_easy);
  });

  // p_argon2i_overlap skipped because pointers are managed by wrapper

  // p_x25519_overlap skipped because pointers are managed by wrapper

  // p_key_exchange_overlap skipped because pointers are managed by wrapper

  it("p_eddsa_roundtrip", async function () {
    const mc = await Monocypher;
    const MESSAGE_SIZE = 30;
    for (let i = 0; i < MESSAGE_SIZE; i++) {
      const message = randomBytes(i);
      const sk = randomBytes(32);
      const pk = mc.crypto_sign_public_key(sk);
      const signature = mc.crypto_sign(sk, pk, message);
      expect(mc.crypto_check(signature, pk, message)).to.be.true;

      // reject forgeries
      const zero = new Uint8Array(64);
      const forgery = new Uint8Array(64);
      for (let j = 0; j < 64; j++) { forgery[j] = signature[j] + 1; }
      expect(mc.crypto_check(zero   , pk, message)).to.be.false;
      expect(mc.crypto_check(forgery, pk, message)).to.be.false;
    }
  });

  // Verifies that random signatures are all invalid.  Uses random
  // public keys to see what happens outside of the curve (it should
  // yield an invalid signature).
  it("p_eddsa_random", async function () {
    const mc = await Monocypher;
    const MESSAGE_SIZE = 30;
    for (let i = 0; i < 100; i++) {
      const message = randomBytes(MESSAGE_SIZE);
      const pk = randomBytes(32);
      const signature = randomBytes(64);
      expect(mc.crypto_check(signature, pk, message)).to.be.false;
    }
    // Testing S == L (for code coverage)
    const message = randomBytes(MESSAGE_SIZE);
    const pk = randomBytes(32);
    const signature = Uint8Array.of(
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
      0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
      0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10
    );
    expect(mc.crypto_check(signature, pk, message)).to.be.false;
  });

  // p_eddsa_overlap skipped because pointers are managed by wrapper

  // p_eddsa_incremental skipped because incremental functions are not implemented

  it("p_aead", async function () {
    const mc = await Monocypher;
    for (let i = 0; i < 1000; i++) {
      const key = randomBytes(32);
      const nonce = randomBytes(24);
      const ad = randomBytes(4);
      const plaintext = randomBytes(8);
      // AEAD roundtrip
      let box = mc.crypto_lock_aead(key, nonce, ad, plaintext);
      let out = mc.crypto_unlock_aead(key, nonce, ad, box);
      expect(out).to.exist;
      expect(out.subarray(16)).to.deep.equal(plaintext);
      box[0]++;
      expect(mc.crypto_unlock_aead(key, nonce, ad, box)).to.be.null;

      // Authenticated roundtrip (easy interface)
      // Make and accept message
      box = mc.crypto_lock(key, nonce, plaintext);
      expect(out = mc.crypto_unlock(key, nonce, box)).to.exist;
      // Make sure decrypted text and original text are the same
      expect(out.subarray(16)).to.deep.equal(plaintext);
      // Make and reject forgery
      box[0]++;
      expect(mc.crypto_unlock(key, nonce, box)).to.be.null;
      box[0]--; // undo forgery

      // Same result for both interfaces
      const box2 = mc.crypto_lock_aead(key, nonce, null, plaintext);
      expect(box2).to.deep.equal(box);
    }
  });

  // Elligator direct mapping must ignore the most significant bits
  it("p_elligator_direct_msb", async function () {
    const mc = await Monocypher;
    for (let i = 0; i < 20; i++) {
      const r = randomBytes(32);
      const r1 = r.slice(0, 32);  r1[31] = (r[31] & 0x3f) | 0x00;
      const r2 = r.slice(0, 32);  r2[31] = (r[31] & 0x3f) | 0x40;
      const r3 = r.slice(0, 32);  r3[31] = (r[31] & 0x3f) | 0x80;
      const r4 = r.slice(0, 32);  r4[31] = (r[31] & 0x3f) | 0xc0;
      const u  = mc.crypto_hidden_to_curve(r);
      expect(mc.crypto_hidden_to_curve(r1)).to.deep.equal(u);
      expect(mc.crypto_hidden_to_curve(r2)).to.deep.equal(u);
      expect(mc.crypto_hidden_to_curve(r3)).to.deep.equal(u);
      expect(mc.crypto_hidden_to_curve(r4)).to.deep.equal(u);
    }
  });

  // p_elligator_direct_overlap skipped because pointers are managed by wrapper

  // p_elligator_inverse_overlap skipped because pointers are managed by wrapper

  it("p_elligator_x25519", async function () {
    const mc = await Monocypher;
    let i = 0;
    while (i < 64) {
      const sk1  = randomBytes(32);
      const sk2  = randomBytes(32);
      const skc  = sk1.slice(0, 32);  skc[0] &= 248;
      const pks  = mc.crypto_x25519_dirty_small(sk1);
      const pksc = mc.crypto_x25519_dirty_small(skc);
      const pkf  = mc.crypto_x25519_dirty_fast (sk1);
      const pkfc = mc.crypto_x25519_dirty_fast (skc);
      const pk1  = mc.crypto_x25519_public_key (sk1);

      // Both dirty functions behave the same
      expect(pkf).to.deep.equal(pks);

      // Dirty functions behave cleanly if we clear the 3 msb first
      expect(pksc).to.deep.equal(pk1);
      expect(pkfc).to.deep.equal(pk1);

      // Dirty functions behave the same as the clean one if the lsb
      // are 0, differently if it is not
      if ((sk1[0] & 7) == 0) { expect(pkf).to.deep.equal(pk1);     }
      else                   { expect(pkf).not.to.deep.equal(pk1); }

      // Maximise tweak diversity.
      // We want to set the bits 1 (sign) and 6-7 (padding)
      const tweak = ((i & 1) + ((i << 5) % 256)) % 256;
      const r = mc.crypto_curve_to_hidden(pkf, tweak);
      if (!r) {
        continue; // retry untill success (doesn't increment the tweak)
      }
      // Verify that the tweak's msb are copied to the representative
      expect((tweak >> 6) % 256).to.equal((r[31] >> 6) % 256);

      // Round trip
      const pkr = mc.crypto_hidden_to_curve(r);
      expect(pkr).to.deep.equal(pkf);

      // Dirty and safe keys are compatible
      const e1 = mc.crypto_x25519(sk2, pk1);
      const e2 = mc.crypto_x25519(sk2, pkr);
      expect(e2).to.deep.equal(e1);
      i++;
    }
  });

  it("p_elligator_key_pair", async function () {
    const mc = await Monocypher;
    for (let i = 0; i < 32; i++) {
      const seed = randomBytes(32);
      const sk2 = randomBytes(32);
      const { hidden: r, secret_key: sk1 } = mc.crypto_hidden_key_pair(seed);
      const pkr = mc.crypto_hidden_to_curve(r);
      const pk1 = mc.crypto_x25519_public_key(sk1);
      const e1  = mc.crypto_x25519(sk2, pk1);
      const e2  = mc.crypto_x25519(sk2, pkr);
      expect(e2).to.deep.equal(e1);
    }
  });

  // p_elligator_key_pair_overlap skipped because pointers are managed by wrapper

  it("p_x25519_inverse", async function () {
    const mc = await Monocypher;
    const b = randomBytes(32);
    // random point (cofactor is cleared).
    const base = mc.crypto_x25519_public_key(b);
    // check round trip
    for (let i = 0; i < 50; i++) {
      const sk = randomBytes(32);
      const pk = mc.crypto_x25519(sk, base);
      const blind = mc.crypto_x25519_inverse(sk, pk);
      expect(base).to.deep.equal(blind);
    }

    // check cofactor clearing
    // (Multiplying by a low order point yields zero
    const low_order = [
      new Uint8Array(32),
      new Uint8Array(32),
      Uint8Array.of(
        0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24,
        0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
        0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86,
        0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57,
      ),
      Uint8Array.of(
        0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae,
        0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
        0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd,
        0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
      )
    ];
    low_order[1][0] = 1;
    const zero = new Uint8Array(32);
    for (let i = 0; i < 32; i++) {
      const sk = randomBytes(32);
      const blind = mc.crypto_x25519_inverse(sk, low_order[i%4]);
      expect(blind).to.deep.equal(zero);
    }
  });

  // p_elligator_inverse_overlap skipped because pointers are managed by wrapper

  it("p_from_eddsa", async function () {
    const mc = await Monocypher;
    for (let i = 0; i < 32; i++) {
      const ed_private = randomBytes(32);
      const ed_public = mc.crypto_sign_public_key   (ed_private);
      const x_private = mc.crypto_from_eddsa_private(ed_private);
      const x_public1 = mc.crypto_from_eddsa_public (ed_public);
      const x_public2 = mc.crypto_x25519_public_key (x_private);
      expect(x_public2).to.deep.equal(x_public1);
    }
  });
});
