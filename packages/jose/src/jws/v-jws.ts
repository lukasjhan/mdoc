import * as v from 'valibot';

import { vJoseHeader } from '../v-jose-protected-header.js';

export const vJwsHeader = v.looseObject({
  ...vJoseHeader.entries,
  alg: v.pipe(
    v.optional(v.string()),
    v.description('JWS "alg" (Algorithm) Header Parameter.')
  ),
  b64: v.pipe(
    v.optional(v.boolean()),
    v.description(
      'This JWS Extension Header Parameter modifies the JWS Payload representation and the JWS Signing Input computation as per {@link https://www.rfc-editor.org/rfc/rfc7797 RFC7797}.'
    )
  ),
  crit: v.pipe(
    v.optional(v.array(v.string())),
    v.description('JWS "crit" (Critical) Header Parameter.')
  ),
});
export type JwsHeader = v.InferInput<typeof vJwsHeader>;

export const vCompactJwsHeader = v.object({
  ...vJwsHeader.entries,
  alg: v.string(),
});
export type CompactJwsHeader = v.InferInput<typeof vCompactJwsHeader>;
