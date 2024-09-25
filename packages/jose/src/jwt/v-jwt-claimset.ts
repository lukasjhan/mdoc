import * as v from 'valibot';

export const vCritOption = v.object({
  crit: v.pipe(
    v.optional(v.record(v.string(), v.boolean())),
    v.description(
      'An object with keys representing recognized "crit" (Critical) Header Parameter names. The value for those is either `true` or `false`. `true` when the Header Parameter MUST be integrity protected, `false` when it\'s irrelevant.'
    )
  ),
});
export type CritOption = v.InferInput<typeof vCritOption>;

export const vVerifyOptions = v.object({
  ...vCritOption.entries,
  algorithms: v.pipe(
    v.optional(v.array(v.string())),
    v.description(
      'A list of accepted JWS "alg" (Algorithm) Header Parameter values. By default all "alg" (Algorithm) values applicable for the used key/secret are allowed. Note: "none" is never accepted.'
    )
  ),
});
export type VerifyOptions = v.InferInput<typeof vVerifyOptions>;

export const vJwtClaimVerificationOptions = v.object({
  audience: v.pipe(
    v.optional(v.union([v.string(), v.array(v.string())])),
    v.description('Expected JWT "aud" (Audience) Claim value(s).')
  ),
  clockTolerance: v.pipe(
    v.optional(v.union([v.number(), v.string()])),
    v.description(
      'Expected clock tolerance. In seconds when number (e.g. 5), or parsed as seconds when a string (e.g. "5 seconds", "10 minutes", "2 hours").'
    )
  ),
  issuer: v.pipe(
    v.optional(v.union([v.string(), v.array(v.string())])),
    v.description('Expected JWT "iss" (Issuer) Claim value(s).')
  ),
  maxTokenAge: v.pipe(
    v.optional(v.union([v.number(), v.string()])),
    v.description(
      'Maximum time elapsed (in seconds) from the JWT "iat" (Issued At) Claim value. In seconds when number (e.g. 5), or parsed as seconds when a string (e.g. "5 seconds", "10 minutes", "2 hours").'
    )
  ),
  subject: v.pipe(
    v.optional(v.string()),
    v.description('Expected JWT "sub" (Subject) Claim value.')
  ),
  typ: v.pipe(
    v.optional(v.string()),
    v.description('Expected JWT "typ" (Type) Header Parameter value.')
  ),
  currentDate: v.pipe(
    v.optional(v.instance(Date)),
    v.description(
      'Date to use when comparing NumericDate claims, defaults to `new Date()`.'
    )
  ),
  requiredClaims: v.pipe(
    v.optional(v.array(v.string())),
    v.description(
      'Array of required Claim Names that must be present in the JWT Claims Set. Default is that: if the issuer option is set, then "iss" must be present; if the audience option is set, then "aud" must be present; if the subject option is set, then "sub" must be present; if the maxTokenAge option is set, then "iat" must be present.'
    )
  ),
});
export type JwtClaimVerificationOptions = v.InferInput<
  typeof vJwtClaimVerificationOptions
>;

export const vJwtVerifyOptions = v.looseObject({
  ...vVerifyOptions.entries,
  ...vJwtClaimVerificationOptions.entries,
});
export type JwtVerifyOptions = v.InferInput<typeof vJwtVerifyOptions>;
