import { getSubtleCrypto } from './get-subtle-crypto.js';

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
export const exportJwk = async (input: {
  key: CryptoKey;
  crypto?: { subtle: SubtleCrypto };
}): Promise<JsonWebKey> => {
  const { key } = input;
  if (!key.extractable) {
    throw new Error('non-extractable CryptoKey cannot be exported as a JWK');
  }

  const subtleCrypto = getSubtleCrypto(input);
  const { ext, key_ops, alg, use, ...jwk } = await subtleCrypto.exportKey(
    'jwk',
    key
  );

  return jwk as JsonWebKey;
};

export const exportRaw = async (input: {
  key: CryptoKey;
  crypto?: { subtle: SubtleCrypto };
}): Promise<Uint8Array> => {
  const { key } = input;
  if (!key.extractable) {
    throw new Error('non-extractable CryptoKey cannot be exported as a JWK');
  }

  const subtleCrypto = getSubtleCrypto(input);
  const raw = await subtleCrypto.exportKey('raw', key);

  return new Uint8Array(raw);
};
