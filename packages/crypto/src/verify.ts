import type { CryptoContext } from './c-crypto.js';
import { withCryptoContext } from './c-crypto.js';
import checkKeyLength from './check-key-length.js';
import { getSignVerifyCryptoKey } from './get-sign-verify-key.js';
import { importJWK } from './key/import.js';
import { subtleDsa } from './subtls-dsa.js';

export const verify = async (
  input: {
    key: CryptoKey;
    alg: string;
    signature: Uint8Array;
    data: Uint8Array;
  },
  _ctx?: CryptoContext
) => {
  const { key, alg, signature, data } = input;
  const cryptoKey = await getSignVerifyCryptoKey(alg, key, 'verify');
  checkKeyLength(alg, cryptoKey);
  const algorithm = subtleDsa(alg, cryptoKey.algorithm);

  const ctx = withCryptoContext(_ctx ?? {});
  try {
    return await ctx.crypto.subtle.verify(
      algorithm,
      cryptoKey,
      signature,
      data
    );
  } catch {
    return false;
  }
};

export const verifyWithJwk = async (
  input: {
    jwk: JsonWebKey;
    alg?: string;
    signature: Uint8Array;
    data: Uint8Array;
  },
  _ctx?: CryptoContext
) => {
  const { jwk, alg, signature, data } = input;
  jwk.alg = jwk.alg ?? alg;
  if (!jwk.alg) throw new Error(`Missing 'alg' value in jwk.`);

  const ctx = withCryptoContext(_ctx ?? {});
  const key = await importJWK({ jwk, alg }, ctx);
  return verify({ key, alg: jwk.alg, signature, data }, ctx);
};
