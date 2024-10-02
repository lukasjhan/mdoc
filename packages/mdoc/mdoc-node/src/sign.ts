import type { JWK } from 'jose';
import checkKeyLength from './check-key-length.js';
import { getSignVerifyCryptoKey } from './get-sign-verify-key.js';
import { importJWK } from './import-jwk.js';
import { subtleDsa } from './subtls-dsa.js';

export type SignFunction = (
  alg: string,
  key: CryptoKey,
  data: Uint8Array
) => Promise<Uint8Array>;

export const sign: SignFunction = async (alg, key, data) => {
  const cryptoKey = await getSignVerifyCryptoKey(alg, key, 'sign');
  checkKeyLength(alg, cryptoKey);
  const signature = await crypto.subtle.sign(
    subtleDsa(alg, cryptoKey.algorithm),
    cryptoKey,
    data
  );
  return new Uint8Array(signature);
};

export type SignWithJwkFunction = (
  jwk: JWK,
  data: Uint8Array
) => Promise<Uint8Array>;

export const signWithJwk: SignWithJwkFunction = async (jwk, data) => {
  const key = await importJWK(jwk);
  if (!jwk.alg) {
    throw new Error(`Missing 'alg' value in jwk.`);
  }
  const alg = jwk.alg;
  const cryptoKey = await getSignVerifyCryptoKey(alg, key, 'sign');
  checkKeyLength(alg, cryptoKey);
  const signature = await crypto.subtle.sign(
    subtleDsa(alg, cryptoKey.algorithm),
    cryptoKey,
    data
  );
  return new Uint8Array(signature);
};
