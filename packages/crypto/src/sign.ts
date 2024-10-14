import type { CryptoContext } from './c-crypto.js';
import { withCryptoContext } from './c-crypto.js';
import checkKeyLength from './check-key-length.js';
import { getSignVerifyCryptoKey } from './get-sign-verify-key.js';
import { importJWK } from './key/import.js';
import { subtleDsa } from './subtls-dsa.js';

export const sign = async (
  input: {
    key: CryptoKey;
    alg: string;
    data: Uint8Array;
  },
  _ctx?: CryptoContext
) => {
  const { key, alg, data } = input;
  const cryptoKey = await getSignVerifyCryptoKey(alg, key, 'sign');
  checkKeyLength(alg, cryptoKey);

  const ctx = withCryptoContext(_ctx ?? {});
  const signature = await ctx.crypto.subtle.sign(
    subtleDsa(alg, cryptoKey.algorithm),
    cryptoKey,
    data
  );
  return new Uint8Array(signature);
};

export const signWithJwk = async (
  input: {
    jwk: JsonWebKey;
    alg?: string;
    data: Uint8Array;
  },
  _ctx?: CryptoContext
) => {
  const { jwk, alg, data } = input;
  jwk.alg = jwk.alg ?? alg;
  if (!jwk.alg) throw new Error(`Missing 'alg' value in jwk.`);

  const ctx = withCryptoContext(_ctx ?? {});
  const key = await importJWK({ jwk, alg }, ctx);
  return sign({ key, alg: jwk.alg, data }, ctx);
};
