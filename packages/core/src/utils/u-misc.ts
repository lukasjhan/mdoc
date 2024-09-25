export const uriEncodeObject = (params: Record<string, unknown>) => {
  return Object.entries(params)
    .map(
      ([key, val]) =>
        `${key}=${encodeURIComponent(typeof val === 'string' || typeof val === 'boolean' || typeof val === 'number' ? val : encodeURIComponent(JSON.stringify(val as Record<string, unknown>)))}`
    )
    .join('&');
};

export function isObject(value: unknown): value is Record<string, unknown> {
  return !!value && !Array.isArray(value) && typeof value === 'object';
}
