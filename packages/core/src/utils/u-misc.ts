export const uriEncodeObject = (obj: Record<string, unknown>) => {
  return Object.entries(obj)
    .map(
      ([key, val]) =>
        `${key}=${encodeURIComponent(typeof val === 'string' || typeof val === 'boolean' || typeof val === 'number' ? val : encodeURIComponent(JSON.stringify(val as Record<string, unknown>)))}`
    )
    .join('&');
};

export function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && !Array.isArray(value) && typeof value === 'object';
}

interface AssertValueSupported<T> {
  supported: T[];
  actual: T;
  error: Error;
  required: boolean;
}

export function assertValueSupported<T>(
  input: AssertValueSupported<T>
): T | undefined {
  const { required, error, supported, actual } = input;
  const intersection = supported.find(value => value === actual);

  if (required && !intersection) throw error;
  return intersection;
}
