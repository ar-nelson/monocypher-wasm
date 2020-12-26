const { readFileSync, writeFileSync } = require('fs');
const { gzipSync } = require('zlib');

const regex = /static const char \*(\w+)_vectors\[\]=\{([^}]+)\}/mg;
const src = readFileSync('vectors.h', { encoding: 'utf8' });
const json = {};

let match;
while ((match = regex.exec(src)) != null) {
  const [,name,vectorsString] = match;
  const vectors = vectorsString.split(/[,\s]+/).filter(x => x.length).map(x => JSON.parse(x));
  json[name] = vectors;
}

writeFileSync('test-vectors.json.gz', gzipSync(JSON.stringify(json), { level: 9 }));
