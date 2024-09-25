import * as v from 'valibot';

export const vJwk = v.looseObject({
  kty: v.string(),
  use: v.optional(v.string()),
  alg: v.optional(v.string()),
  crv: v.optional(v.string()),
  d: v.optional(v.string()),
  dp: v.optional(v.string()),
  dq: v.optional(v.string()),
  e: v.optional(v.string()),
  ext: v.optional(v.boolean()),
  k: v.optional(v.string()),
  key_ops: v.optional(v.array(v.string())),
  kid: v.optional(v.string()),
  n: v.optional(v.string()),
  oth: v.optional(
    v.array(
      v.object({
        d: v.optional(v.string()),
        r: v.optional(v.string()),
        t: v.optional(v.string()),
      })
    )
  ),
  p: v.optional(v.string()),
  q: v.optional(v.string()),
  qi: v.optional(v.string()),
  /** JWK "use" (Public Key Use) Parameter. */
  x: v.optional(v.string()),
  y: v.optional(v.string()),
  /** JWK "x5c" (X.509 Certificate Chain) Parameter. */
  x5c: v.optional(v.array(v.string())),
  /** JWK "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter. */
  x5t: v.optional(v.string()),
  /** "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter. */
  'x5t#S256': v.optional(v.string()),
  /** JWK "x5u" (X.509 URL) Parameter. */
  x5u: v.optional(v.string()),
});

export type Jwk = v.InferInput<typeof vJwk>;

export const vJwks = v.object({
  keys: v.array(vJwk),
});

export type Jwks = v.InferInput<typeof vJwks>;
