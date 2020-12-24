const { readFileSync, writeFileSync } = require('fs');
const { gzipSync } = require('zlib');

const lines = readFileSync('vectors.h', { encoding: 'utf8' }).split('\n');
const bindings = new Map();

for (const line of lines) {
  const match = /^static \w+ \*?(\w+)\[\]=\{([^}]+)\,}/.exec(line);
  if (match) {
    bindings.set(match[1], match[2].split(','));
  }
}

const json = [...bindings.keys()]
  .map(k => /^(\w+)_vectors$/.exec(k))
  .filter(k => k)
  .map(([k,name]) => ({
    name,
    vectors: bindings.get(k)
      .map((vecName, i) => {
        const vec = bindings.get(vecName);
        return vec ? Buffer.from(vec.map(x => +x)).toString('hex') : null;
      })
  }))
  .reduce((obj, { name, vectors }) => ({ ...obj, [name]: vectors }), {});

writeFileSync('test-vectors.json.gz', gzipSync(JSON.stringify(json), { level: 9 }));
