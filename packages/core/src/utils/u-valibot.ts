import * as v from 'valibot';

export const vDidMethod = v.custom<`did:${string}`>(
  input => {
    if (typeof input !== 'string') return false;

    const parts = input.split(':');

    const nonEmptyParts =
      parts.length >= 2 &&
      parts.every(part => typeof part === 'string' && part.length > 0);

    return nonEmptyParts && input.startsWith('did:');
  },
  customIssue =>
    `Expected did method, received '${typeof customIssue.input === 'string' ? customIssue.input : 'not a string'}'.`
);

export const vDid = v.custom<`did:${string}:${string}`>(
  input => {
    return typeof input === 'string'
      ? input.startsWith('did:') && input.split(':').length >= 3
      : false;
  },
  customIssue =>
    `Expected did, received '${typeof customIssue.input === 'string' ? customIssue.input : 'not a string'}'.`
);

export const vHttpsUrl = v.pipe(
  v.string(),
  v.url(),
  // TODO: IN PROD ONLY ALLOW HTTPS
  v.regex(/^https?:/)
);

export const objectToUndefinedIfNoValue = <
  T extends Record<string, unknown> | undefined | null,
>(
  record: T
): T | undefined => {
  if (!record) return undefined;

  return Object.values(record).some(val => !!val) ? record : undefined;
};

export const nullToUndefined = <T>(value: T) => {
  return value ?? undefined;
};

export function emptyArrayToUndefined<T>(
  array: T[] | null | undefined
): [T, ...T[]] | undefined {
  return array && array.length > 0 ? (array as [T, ...T[]]) : undefined;
}

export const vSpaceSeparatedString = v.pipe(
  v.string(),
  v.transform(val => val.split(' '))
);

export const vUint8Array = v.instance(Uint8Array);
