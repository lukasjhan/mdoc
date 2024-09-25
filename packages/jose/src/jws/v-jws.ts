import * as v from 'valibot';

import { emptyArrayToUndefined } from '@protokoll/core';

import { vJoseHeaderParameters } from '../v-jose.js';

export const vJwsHeaderParameters = v.looseObject({
  ...vJoseHeaderParameters.entries,
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
    v.transform(emptyArrayToUndefined),
    v.description('JWS "crit" (Critical) Header Parameter.')
  ),
});
export type JwsHeaderParameters = v.InferInput<typeof vJwsHeaderParameters>;
