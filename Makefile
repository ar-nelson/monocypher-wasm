MONOCYPHER_VERSION = 3.1.2
PACKAGE_VERSION = 4

COMPILE_FLAGS = -Wall \
	--target=wasm32 \
	-Os \
	-nostdlib \
	-fvisibility=hidden \
	-std=c11 \
	-ffunction-sections \
	-fdata-sections \
	-mbulk-memory \
	-DPRINTF_DISABLE_SUPPORT_FLOAT=1 \
	-DPRINTF_DISABLE_SUPPORT_LONG_LONG=1 \
	-DPRINTF_DISABLE_SUPPORT_PTRDIFF_T=1

.PHONY: all npm check test clean

all: npm monocypher.min.js
npm: test
	deno run -A scripts/build_npm.ts $(MONOCYPHER_VERSION)-$(PACKAGE_VERSION)

test: monocypher_wasm.ts test-vectors.json.gz check
	deno test --allow-read=test-vectors.json.gz

check:
	deno fmt
	deno lint

clean:
	rm -rf build buildNpmTest walloc.o monocypher.o

monocypher.min.js: mod.ts monocypher_wasm.ts Makefile
	deno bundle mod.ts | esbuild --minify > monocypher.min.js

monocypher_wasm.ts: monocypher.wasm scripts/wasm_to_ts.ts Makefile
	deno run scripts/wasm_to_ts.ts < monocypher.wasm > monocypher_wasm.ts

monocypher.wasm: monocypher.o walloc.o Makefile
	wasm-ld -o monocypher.wasm --no-entry --strip-all -error-limit=0 --lto-O3 -O3 --gc-sections \
		--export malloc \
		--export free \
		--export crypto_argon2i \
		--export crypto_argon2i_general \
		--export crypto_blake2b \
		--export crypto_blake2b_general \
		--export crypto_chacha20 \
		--export crypto_xchacha20 \
		--export crypto_curve_to_hidden \
		--export crypto_hidden_to_curve \
		--export crypto_hidden_key_pair \
		--export crypto_from_eddsa_private \
		--export crypto_from_eddsa_public \
		--export crypto_hchacha20 \
		--export crypto_ietf_chacha20 \
		--export crypto_key_exchange \
		--export crypto_lock \
		--export crypto_unlock \
		--export crypto_lock_aead \
		--export crypto_unlock_aead \
		--export crypto_poly1305 \
		--export crypto_sign_public_key \
		--export crypto_sign \
		--export crypto_check \
		--export crypto_verify16 \
		--export crypto_verify32 \
		--export crypto_verify64 \
		--export crypto_wipe \
		--export crypto_x25519 \
		--export crypto_x25519_public_key \
		--export crypto_x25519_dirty_fast \
		--export crypto_x25519_dirty_small \
		--export crypto_x25519_inverse \
		monocypher.o walloc.o

walloc.o: walloc.c Makefile
	clang -c $(COMPILE_FLAGS) -o walloc.o walloc.c

monocypher.o: monocypher.c monocypher.h Makefile
	clang -c $(COMPILE_FLAGS) -o monocypher.o monocypher.c

test-vectors.json.gz: vectors.h scripts/build-test-vectors.ts Makefile
	deno run scripts/build-test-vectors.ts < vectors.h > test-vectors.json.gz

monocypher.c monocypher.h vectors.h &: Makefile
	curl https://monocypher.org/download/monocypher-$(MONOCYPHER_VERSION).tar.gz | tar -xzv --no-anchored --overwrite --strip-components=2 src/monocypher.c src/monocypher.h tests/vectors.h
	touch monocypher.c
	touch monocypher.h
	touch vectors.h
