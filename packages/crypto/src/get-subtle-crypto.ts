export const getSubtleCrypto = (input: {
  crypto?: { subtle: SubtleCrypto };
}) => {
  const subtleCrypto = input.crypto?.subtle ?? crypto.subtle;
  // eslint-disable-next-line @typescript-eslint/no-unnecessary-condition
  if (!subtleCrypto) {
    throw new Error(
      'Subtle-Crypto was neither provided nor is it available globally.'
    );
  }

  return subtleCrypto;
};
