import { readAllSync } from 'https://deno.land/std@0.150.0/streams/conversion.ts';
import { gzip } from 'https://deno.land/x/compress@v0.4.3/gzip/mod.ts';

const regex = /static const char \*(\w+)_vectors\[\]=\{([^}]+)\}/mg;
const src = new TextDecoder().decode(readAllSync(Deno.stdin));
const json: Record<string, unknown> = {};

let match: RegExpExecArray | null;
while ((match = regex.exec(src)) != null) {
  const [, name, vectorsString] = match;
  const vectors = vectorsString.split(/[,\s]+/).filter((x) => x.length).map((x) => JSON.parse(x));
  json[name] = vectors;
}

Deno.stdout.write(gzip(new TextEncoder().encode(JSON.stringify(json)), { level: 9 }));
