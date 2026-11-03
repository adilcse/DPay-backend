/**
 * Generates a P-256 issuer key pair: `issuer-key.pem` (PKCS#8, keep secret; in production use an
 * HSM) and prints the public key in the forms the app pins (SPKI base64 for `X509EncodedKeySpec`).
 *
 *   npm run gen:issuer-key -- ./secrets/issuer-key.pem
 */
import { generateKeyPairSync } from 'node:crypto';
import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';

const out = process.argv[2] ?? './secrets/issuer-key.pem';
if (existsSync(out)) {
  console.error(`${out} already exists; refusing to overwrite an issuer key.`);
  process.exit(1);
}
const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
mkdirSync(dirname(out), { recursive: true });
writeFileSync(out, privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
console.log(`Wrote ${out}`);
console.log('Public key (SPKI, base64) to pin in the app TrustAnchors:');
console.log(publicKey.export({ format: 'der', type: 'spki' }).toString('base64'));
