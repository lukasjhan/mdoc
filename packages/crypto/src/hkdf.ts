import { getSubtleCrypto } from './get-subtle-crypto.js';

export const hkdf = async (input: {
  digest: 'sha1' | 'sha256' | 'sha384' | 'sha512';
  ikm: Uint8Array;
  salt: Uint8Array;
  info: Uint8Array;
  keylen: number;
  crypto?: { subtle: SubtleCrypto };
}): Promise<Uint8Array> => {
  const { digest, ikm, salt, info, keylen } = input;

  const subtleCrypto = getSubtleCrypto(input);
  return new Uint8Array(
    await subtleCrypto.deriveBits(
      {
        name: 'HKDF',
        hash: `SHA-${digest.substr(3)}`,
        salt,
        info,
      },
      await subtleCrypto.importKey('raw', ikm, 'HKDF', false, ['deriveBits']),
      keylen << 3
    )
  );
};
