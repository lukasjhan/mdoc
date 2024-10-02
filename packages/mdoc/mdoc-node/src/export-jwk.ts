import type { JWK } from 'jose';

const keyToJWK = async (input: {
  key: CryptoKey;
  crypto?: { subtle: SubtleCrypto };
}): Promise<JWK> => {
  const { key } = input;
  if (!key.extractable) {
    throw new Error('non-extractable CryptoKey cannot be exported as a JWK');
  }

  const subtleCrypto = input.crypto?.subtle ?? crypto.subtle;
  const { ext, key_ops, alg, use, ...jwk } = await subtleCrypto.exportKey(
    'jwk',
    key
  );

  return jwk as JWK;
};
export default keyToJWK;
