import * as v from 'valibot';

import { emptyArrayToUndefined } from '@protokoll/core';

import { vJoseHeaderParameters } from '../v-jose.js';

export const vJweHeaderParameters = v.looseObject({
  ...vJoseHeaderParameters.entries,
  alg: v.pipe(
    v.optional(v.string()),
    v.description('JWE "alg" (Algorithm) Header Parameter.')
  ),
  enc: v.pipe(
    v.optional(v.string()),
    v.description('JWE "enc" (Encryption Algorithm) Header Parameter.')
  ),
  crit: v.pipe(
    v.optional(v.array(v.string())),
    v.transform(emptyArrayToUndefined),
    v.description('JWE "crit" (Critical) Header Parameter.')
  ),
  zip: v.pipe(
    v.optional(v.string()),
    v.description(
      'JWE "zip" (Compression Algorithm) Header Parameter. This parameter is not supported anymore.'
    )
  ),
});
export type JweHeaderParameters = v.InferInput<typeof vJweHeaderParameters>;

/** Recognized Compact JWE Header Parameters, any other Header Members may also be present. */
export const vCompactJweHeaderParameters = v.looseObject({
  ...vJweHeaderParameters.entries,
  alg: v.string(),
  enc: v.string(),
});

export type CompactJweHeaderParameters = v.InferInput<
  typeof vCompactJweHeaderParameters
>;
