import * as v from 'valibot';

import { vCritOption } from '../jwt/v-jwt-claimset.js';
import { vJoseHeader } from '../v-jose-protected-header.js';

export const vJweHeader = v.looseObject({
  ...vJoseHeader.entries,
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
    v.description('JWE "crit" (Critical) Header Parameter.')
  ),
  zip: v.pipe(
    v.optional(v.string()),
    v.description(
      'JWE "zip" (Compression Algorithm) Header Parameter. This parameter is not supported anymore.'
    )
  ),
});
export type JweHeader = v.InferInput<typeof vJweHeader>;

/** Recognized Compact JWE Header Parameters, any other Header Members may also be present. */
export const vCompactJweHeader = v.looseObject({
  ...vJweHeader.entries,
  alg: v.string(),
  enc: v.string(),
});
export type CompactJweHeader = v.InferInput<typeof vCompactJweHeader>;

export const vDecryptOptions = v.looseObject({
  ...vCritOption.entries,
  keyManagementAlgorithms: v.pipe(
    v.optional(v.array(v.string())),
    v.description(
      'A list of accepted JWE "alg" (Algorithm) Header Parameter values. By default all "alg" (Algorithm) Header Parameter values applicable for the used key/secret are allowed except for all PBES2 Key Management Algorithms, these need to be explicitly allowed using this option.'
    )
  ),
  contentEncryptionAlgorithms: v.pipe(
    v.optional(v.array(v.string())),
    v.description(
      'A list of accepted JWE "enc" (Encryption Algorithm) Header Parameter values. By default all "enc" (Encryption Algorithm) values applicable for the used key/secret are allowed.'
    )
  ),
  maxPBES2Count: v.pipe(
    v.optional(v.number()),
    v.description(
      'Maximum allowed "p2c" (PBES2 Count) Header Parameter value. The PBKDF2 iteration count defines the algorithm\'s computational expense. By default this value is set to 10000.'
    )
  ),
});
export type DecryptOptions = v.InferInput<typeof vDecryptOptions>;
