import { toPKCS8 as exportPrivate, toSPKI as exportPublic } from '../asn1.js';
import type { CryptoContext } from '../c-crypto.js';
import { withCryptoContext } from '../c-crypto.js';

/**
 * Exports a runtime-specific public key representation ({@link !KeyObject} or {@link !CryptoKey}) to
 * a PEM-encoded SPKI string format.
 *
 * This function is exported (as a named export) from the main `'jose'` module entry point as well
 * as from its subpath export `'jose/key/export'`.
 *
 * @example
 *
 * ```js
 * const spkiPem = await jose.exportSPKI(publicKey)
 *
 * console.log(spkiPem)
 * ```
 *
 * @param key Key representation to transform to a PEM-encoded SPKI string format.
 */
export async function exportSPKI(
  input: { key: CryptoKey },
  _ctx?: CryptoContext
): Promise<string> {
  const ctx = withCryptoContext(_ctx ?? {});
  return exportPublic(input, ctx);
}

/**
 * Exports a runtime-specific private key representation ({@link !KeyObject} or {@link !CryptoKey}) to
 * a PEM-encoded PKCS8 string format.
 *
 * This function is exported (as a named export) from the main `'jose'` module entry point as well
 * as from its subpath export `'jose/key/export'`.
 *
 * @example
 *
 * ```js
 * const pkcs8Pem = await jose.exportPKCS8(privateKey)
 *
 * console.log(pkcs8Pem)
 * ```
 *
 * @param key Key representation to transform to a PEM-encoded PKCS8 string format.
 */
export async function exportPKCS8(
  input: { key: CryptoKey },
  _ctx?: CryptoContext
): Promise<string> {
  const ctx = withCryptoContext(_ctx ?? {});
  return exportPrivate(input, ctx);
}

/**
 * Exports a runtime-specific key representation (KeyLike) to a JWK.
 *
 * This function is exported (as a named export) from the main `'jose'` module entry point as well
 * as from its subpath export `'jose/key/export'`.
 *
 * @example
 *
 * ```js
 * const privateJwk = await jose.exportJWK(privateKey)
 * const publicJwk = await jose.exportJWK(publicKey)
 *
 * console.log(privateJwk)
 * console.log(publicJwk)
 * ```
 *
 * @param key Key representation to export as JWK.
 */
export const exportJwk = async (
  input: {
    key: CryptoKey;
  },
  _ctx?: CryptoContext
): Promise<JsonWebKey> => {
  const { key } = input;

  if (!key.extractable) {
    throw new Error('non-extractable CryptoKey cannot be exported as a JWK');
  }

  const ctx = withCryptoContext(_ctx ?? {});
  const { ext, key_ops, alg, use, ...jwk } = await ctx.crypto.subtle.exportKey(
    'jwk',
    key
  );

  return jwk as JsonWebKey;
};

export const exportRaw = async (
  input: {
    key: CryptoKey;
  },
  _ctx?: CryptoContext
): Promise<Uint8Array> => {
  const { key } = input;
  if (!key.extractable) {
    throw new Error('non-extractable CryptoKey cannot be exported as a JWK');
  }

  const ctx = withCryptoContext(_ctx ?? {});
  const raw = await ctx.crypto.subtle.exportKey('raw', key);
  return new Uint8Array(raw);
};
