// Development only. Canonical input is the Rust schemars output in contracts/.
import { readFile, readdir, mkdir, writeFile } from 'node:fs/promises';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { compile } from 'json-schema-to-typescript';
import Ajv2020 from 'ajv/dist/2020.js';
import standaloneCode from 'ajv/dist/standalone/index.js';
import { _ } from 'ajv/dist/compile/codegen/index.js';
import { build } from 'esbuild';
const root = new URL('../../../', import.meta.url);
const output = new URL('../generated/', import.meta.url);
const check = process.argv.slice(2).join(' ') === '--check';
if (process.argv.length > (check ? 3 : 2)) throw new Error('usage: generate.mjs [--check]');
const files = (await readdir(new URL('contracts/', root))).filter(n => n.endsWith('.schema.json')).sort();
const artifacts = new Map();
const exports = {};
const types = [];
const ajv = new Ajv2020({ strict: true, strictTypes: false, validateFormats: false, code: { source: true, esm: true }, allErrors: false });
ajv.addKeyword({ keyword: 'x-lomi-maxUtf8Bytes', type: 'string', schemaType: 'number', code(cxt) {
  cxt.fail(_`new TextEncoder().encode(${cxt.data}).length > ${cxt.schema}`);
}});
ajv.addKeyword({ keyword: 'x-lomi-maxUtf16CodeUnits', type: 'string', schemaType: 'number', code(cxt) {
  cxt.fail(_`${cxt.data}.length > ${cxt.schema}`);
}});
let declarations = '// Generated from Rust JSON schemas. Do not edit.\n';
for (const [i, file] of files.entries()) {
  const name = file.replace('.schema.json', '');
  const schema = JSON.parse(await readFile(new URL(`contracts/${file}`, root), 'utf8'));
  const exportName = `contractValidator${i}`;
  const id = `urn:lomi:e0:${name}`;
  ajv.addSchema({ ...schema, $id: id }, id);
  exports[exportName] = id;
  const typeName = schema.title;
  artifacts.set(`${name}.d.ts`, await compile(schema, typeName, { bannerComment: '// Generated from Rust JSON schema. Do not edit.', maxItems: 0, additionalProperties: false, format: true }));
  declarations += `import type { ${typeName} as T${i} } from './${name}.js';\nexport type { ${typeName} as ${typeName}Contract } from './${name}.js';\n`;
  types.push(`  ${JSON.stringify(name)}: T${i};`);
}
// esbuild resolves Ajv's generated CommonJS helper imports at development time.
// The emitted runtime is a self-contained ES module without require/Node builtins.
const source = standaloneCode(ajv, exports);
const bundled = await build({ stdin: { contents: source, resolveDir: fileURLToPath(new URL('../', import.meta.url)), loader: 'js' }, bundle: true, platform: 'browser', format: 'esm', write: false, minify: true, legalComments: 'none', metafile: true });
const validators = bundled.outputFiles[0].text;
if (Object.values(bundled.metafile.outputs).some(o => o.imports.length)) throw new Error('generated validators retain external runtime dependency');
artifacts.set('validators.mjs', validators);
artifacts.set('registry.mjs', `// Generated. Do not edit.\nimport * as v from './validators.mjs';\nexport const validators = Object.freeze({\n${files.map((f,i)=>`  ${JSON.stringify(f.replace('.schema.json',''))}: v.contractValidator${i}`).join(',\n')}\n});\n`);
declarations += `export interface ContractMap {\n${types.join('\n')}\n}\nexport type ContractName = keyof ContractMap;\nexport declare function initializeCanonicalCodec(adapter: { validateWire(kind: string, json: string): void; validateResponseFor(requestJson: string, responseJson: string): void }): void;\nexport declare function validateShape<K extends ContractName>(name: K, value: unknown): value is ContractMap[K];\nexport declare function decodeShape<K extends ContractName>(name: K, json: string): ContractMap[K];\nexport declare function validate<K extends ContractName>(name: K, value: unknown): value is ContractMap[K];\nexport declare function decode<K extends ContractName>(name: K, json: string): ContractMap[K];\nexport declare function decodeResponse(request: ContractMap['rpc-request'], json: string): ContractMap['rpc-response'];\nexport declare function checkResponse(request: ContractMap['rpc-request'], response: unknown): response is ContractMap['rpc-response'];\nexport declare class OrderedSequence { accept(sequence: string): boolean; reset(): void; }\n`;
artifacts.set('index.d.ts', declarations);
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const inputs = {};
for (const file of files) inputs[`contracts/${file}`] = hash(await readFile(new URL(`contracts/${file}`, root)));
for (const file of ['package.json','package-lock.json','scripts/generate.mjs','src/index.mjs']) inputs[`packages/remote-contracts/${file}`] = hash(await readFile(new URL(`../${file}`,import.meta.url)));
artifacts.set('manifest.json', JSON.stringify({ status: 'draft-e0', inputPathBase: 'repository', artifactPathBase: 'packages/remote-contracts/generated', runtime: 'self-contained browser/native ESM; Node development only', inputs, artifacts: Object.fromEntries([...artifacts].map(([n,v])=>[n,hash(v)])), manifestSelfHash: false }, null, 2)+'\n');
await mkdir(output, { recursive: true });
for (const [name, contents] of artifacts) {
  const target = new URL(name, output);
  if (check) {
    if (await readFile(target,'utf8').catch(()=>null) !== contents) throw new Error(`generated client drift: ${name}`);
  } else await writeFile(target, contents);
}
const actual = await readdir(output);
for (const file of actual) if (!artifacts.has(file)) throw new Error(`unexpected generated artifact: ${file}`);
console.log(`${check ? 'Checked' : 'Generated'} ${files.length} schemas, declarations, standalone validators and hashes.`);
