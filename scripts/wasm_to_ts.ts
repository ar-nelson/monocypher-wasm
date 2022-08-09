let str = '', read: number | null = 0;
const buf = new Uint8Array(48);
while ((read = await Deno.stdin.read(buf)) !== null) {
  for (let i = 0; i < read; i++) str += `${buf[i]},`;
  str += '\n';
}
console.log(`// deno-fmt-ignore-file
const WASM_BIN = new Uint8Array([
${str}]);
export default WASM_BIN;`);
