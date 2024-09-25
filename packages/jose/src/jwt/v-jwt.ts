import * as v from 'valibot';

import { emptyArrayToUndefined } from '@protokoll/core';

export const vJwtPayload = v.looseObject({
  iss: v.pipe(
    v.optional(v.string()),
    v.description(
      'JWT Issuer {@see @link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.1 RFC7519#section-4.1.1}'
    )
  ),
  sub: v.pipe(
    v.optional(v.string()),
    v.description(
      'JWT Subject {@see @link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.2 RFC7519#section-4.1.2}'
    )
  ),
  aud: v.pipe(
    v.optional(
      v.union([
        v.string(),
        v.pipe(v.array(v.string()), v.transform(emptyArrayToUndefined)),
      ])
    ),
    v.description(
      'JWT Audience {@see @link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.3 RFC7519#section-4.1.3}'
    )
  ),
  jti: v.pipe(
    v.optional(v.string()),
    v.description(
      'JWT ID {@see @link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.7 RFC7519#section-4.1.7}'
    )
  ),
  nbf: v.pipe(
    v.optional(v.number()),
    v.description(
      'JWT Not Before {@see @link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.5 RFC7519#section-4.1.5}'
    )
  ),
  exp: v.pipe(
    v.optional(v.number()),
    v.description(
      'JWT Expiration Time {@see @link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4 RFC7519#section-4.1.4}'
    )
  ),
  iat: v.pipe(
    v.optional(v.number()),
    v.description(
      'JWT Issued At {@see @link https://www.rfc-editor.org/rfc/rfc7519#section-4.1.6 RFC7519#section-4.1.6}'
    )
  ),
});

export type JwtPayload = v.InferInput<typeof vJwtPayload>;
