import type { CryptoContext } from './c-crypto.js';
import { withCryptoContext } from './c-crypto.js';

export const hkdf = async (
  input: {
    digest: 'sha1' | 'sha256' | 'sha384' | 'sha512';
    ikm: Uint8Array;
    salt: Uint8Array;
    info: Uint8Array;
    keylen: number;
  },
  _ctx?: CryptoContext
): Promise<Uint8Array> => {
  const { digest, ikm, salt, info, keylen } = input;

  const ctx = withCryptoContext(_ctx ?? {});
  return new Uint8Array(
    await ctx.crypto.subtle.deriveBits(
      {
        name: 'HKDF',
        hash: `SHA-${digest.substr(3)}`,
        salt,
        info,
      },
      await ctx.crypto.subtle.importKey('raw', ikm, 'HKDF', false, [
        'deriveBits',
      ]),
      keylen << 3
    )
  );
};
