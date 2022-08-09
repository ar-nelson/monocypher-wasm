// ex. scripts/build_npm.ts
import { build, emptyDir } from 'https://deno.land/x/dnt@0.30.0/mod.ts';

const pkg = {
  name: 'monocypher-wasm',
  version: Deno.args[0],
  description: 'WASM port of Monocypher (https://monocypher.org/)',
  author: 'Adam Nelson <adam@nels.onl>',
  homepage: 'https://github.com/ar-nelson/monocypher-wasm#readme',
  license: 'CC0',
  repository: {
    'type': 'git',
    'url': 'https://github.com/ar-nelson/monocypher-wasm.git',
  },
} as const;

// Separate test and release builds because dnt insists on transpiling and
// generating declarations for test files and all of their dependencies.

await emptyDir('./buildNpmTest');

await build({
  shims: {
    deno: 'dev',
    crypto: 'dev',
  },
  typeCheck: false,
  declaration: false,
  entryPoints: ['./mod.ts'],
  outDir: './buildNpmTest',
  package: { ...pkg, private: true },
});

await emptyDir('./build');

await build({
  shims: {},
  compilerOptions: {
    lib: ['esnext', 'dom'],
  },
  test: false,
  entryPoints: ['./mod.ts'],
  outDir: './build',
  package: pkg,
});

Deno.copyFileSync('LICENSE.md', 'build/LICENSE.md');
Deno.copyFileSync('README.md', 'build/README.md');
