export interface CryptoContext {
  crypto: { subtle: SubtleCrypto };
}

export const withCryptoContext = <T extends Partial<CryptoContext>>(
  input: T
): T & CryptoContext => {
  const subtleCrypto = input.crypto?.subtle ?? crypto.subtle;
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  if (!subtleCrypto) {
    throw new Error(
      'Subtle-Crypto was neither provided nor is it available globally.'
    );
  }

  return {
    ...input,
    crypto: { subtle: subtleCrypto },
  };
};
