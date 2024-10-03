import checkKeyLength from './check-key-length.js';
import { getSignVerifyCryptoKey } from './get-sign-verify-key.js';
import { getSubtleCrypto } from './get-subtle-crypto.js';
import { importJWK } from './import.js';
import { subtleDsa } from './subtls-dsa.js';

export const sign = async (input: {
  key: CryptoKey;
  alg: string;
  data: Uint8Array;
  crypto?: { subtle: SubtleCrypto };
}) => {
  const { key, alg, data } = input;
  const cryptoKey = await getSignVerifyCryptoKey(alg, key, 'sign');
  checkKeyLength(alg, cryptoKey);

  const subtleCrypto = getSubtleCrypto(input);
  const signature = await subtleCrypto.sign(
    subtleDsa(alg, cryptoKey.algorithm),
    cryptoKey,
    data
  );
  return new Uint8Array(signature);
};

export const signWithJwk = async (input: {
  jwk: JsonWebKey;
  alg?: string;
  data: Uint8Array;
  crypto?: { subtle: SubtleCrypto };
}) => {
  const { jwk, alg, data } = input;
  jwk.alg = jwk.alg ?? alg;
  if (!jwk.alg) throw new Error(`Missing 'alg' value in jwk.`);

  const key = await importJWK({ jwk, alg, crypto: input.crypto });
  return sign({ key, alg: jwk.alg, data, crypto: input.crypto });
};
