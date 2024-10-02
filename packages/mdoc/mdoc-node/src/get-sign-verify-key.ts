import { checkSigCryptoKey } from './crypto-key.js';

// eslint-disable-next-line @typescript-eslint/require-await
export async function getSignVerifyCryptoKey(
  alg: string,
  key: CryptoKey,
  usage: KeyUsage
) {
  // todo: this is still missing
  //if (usage === 'sign') {
  //key = await normalize.normalizePrivateKey(key, alg);
  //}

  //if (usage === 'verify') {
  //key = await normalize.normalizePublicKey(key, alg);
  //}

  checkSigCryptoKey(key, alg, usage);
  return key;
}
