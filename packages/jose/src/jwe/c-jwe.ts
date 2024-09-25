import * as v from 'valibot';

import type { MaybePromise } from '@protokoll/core';

import { vJwk } from '../jwk/v-jwk.js';
import { vJwtPayload } from '../jwt/v-jwt.js';
import { vProtectedHeaderParameters } from '../v-protected-header.js';

export const vJoseJweJwtDecrypt = v.object({
  jwe: v.string(),
  jwk: vJwk,
});

export const vJoseJweJwtDecryptOut = v.object({
  payload: vJwtPayload,
  protectedHeader: vProtectedHeaderParameters,
});

export type JoseJweJwtDecrypt = (
  input: v.InferInput<typeof vJoseJweJwtDecrypt>
) => MaybePromise<v.InferOutput<typeof vJoseJweJwtDecryptOut>>;

export interface JoseJweContext {
  jose: {
    jwe: { jwtDecrypt: JoseJweJwtDecrypt };
  };
}
