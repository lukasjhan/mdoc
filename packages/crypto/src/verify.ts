import checkKeyLength from './check-key-length.js';
import { getSignVerifyCryptoKey } from './get-sign-verify-key.js';
import { importJWK } from './import.js';
import { subtleDsa } from './subtls-dsa.js';

export const verify = async (input: {
  key: CryptoKey;
  alg: string;
  signature: Uint8Array;
  data: Uint8Array;
  crypto?: { subtle: SubtleCrypto };
}) => {
  const { key, alg, signature, data } = input;
  const cryptoKey = await getSignVerifyCryptoKey(alg, key, 'verify');
  checkKeyLength(alg, cryptoKey);
  const algorithm = subtleDsa(alg, cryptoKey.algorithm);
  const subtleCrypto = input.crypto?.subtle ?? crypto.subtle;
  try {
    return await subtleCrypto.verify(algorithm, cryptoKey, signature, data);
  } catch {
    return false;
  }
};

export const verifyWithJwk = async (input: {
  jwk: JsonWebKey;
  alg?: string;
  signature: Uint8Array;
  data: Uint8Array;
  crypto?: { subtle: SubtleCrypto };
}) => {
  const { jwk, alg, signature, data } = input;
  jwk.alg = jwk.alg ?? alg;
  if (!jwk.alg) throw new Error(`Missing 'alg' value in jwk.`);

  const key = await importJWK({ jwk, alg, crypto: input.crypto });
  return verify({ key, alg: jwk.alg, signature, data, crypto: input.crypto });
};
