import * as v from 'valibot';

import { vJwk } from './jwk/v-jwk.js';

export const vJoseHeaderParameters = v.looseObject({
  kid: v.pipe(
    v.optional(v.string()),
    v.description('"kid" (Key ID) Header Parameter.')
  ),
  x5t: v.pipe(
    v.optional(v.string()),
    v.description(
      '"x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter.'
    )
  ),
  x5c: v.pipe(
    v.optional(v.array(v.string())),
    v.description('"x5c" (X.509 Certificate Chain) Header Parameter.')
  ),
  x5u: v.pipe(
    v.optional(v.string()),
    v.description('"x5u" (X.509 URL) Header Parameter.')
  ),
  jku: v.pipe(
    v.optional(v.string()),
    v.description('"jku" (JWK Set URL) Header Parameter.')
  ),
  jwk: v.pipe(
    v.optional(v.pick(vJwk, ['kty', 'crv', 'x', 'y', 'e', 'n'])),
    v.description('"jwk" (JSON Web Key) Header Parameter.')
  ),
  typ: v.pipe(
    v.optional(v.string()),
    v.description('"typ" (Type) Header Parameter.')
  ),
  cty: v.pipe(
    v.optional(v.string()),
    v.description('"cty" (Content Type) Header Parameter.')
  ),
});
export type JoseHeaderParameters = v.InferInput<typeof vJoseHeaderParameters>;
