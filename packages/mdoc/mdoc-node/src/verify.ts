import type { JWK } from 'jose';
import checkKeyLength from './check-key-length.js';
import { getSignVerifyCryptoKey } from './get-sign-verify-key.js';
import { importJWK } from './import-jwk.js';
import { subtleDsa } from './subtls-dsa.js';

export type VerifyFunction = (
  alg: string,
  key: CryptoKey,
  signature: Uint8Array,
  data: Uint8Array
) => Promise<boolean>;

export const verify: VerifyFunction = async (alg, key, signature, data) => {
  const cryptoKey = await getSignVerifyCryptoKey(alg, key, 'verify');
  checkKeyLength(alg, cryptoKey);
  const algorithm = subtleDsa(alg, cryptoKey.algorithm);
  try {
    return await crypto.subtle.verify(algorithm, cryptoKey, signature, data);
  } catch {
    return false;
  }
};

export type VerifyWithJwkFunction = (
  jwk: JWK,
  signature: Uint8Array,
  data: Uint8Array
) => Promise<boolean>;

export const verifyWithJwk: VerifyWithJwkFunction = async (
  jwk,
  signature,
  data
) => {
  const key = await importJWK(jwk);
  if (!jwk.alg) {
    throw new Error(`Missing 'alg' value in jwk.`);
  }
  const cryptoKey = await getSignVerifyCryptoKey(jwk.alg, key, 'verify');
  checkKeyLength(jwk.alg, cryptoKey);
  const algorithm = subtleDsa(jwk.alg, cryptoKey.algorithm);
  try {
    return await crypto.subtle.verify(algorithm, cryptoKey, signature, data);
  } catch {
    return false;
  }
};
