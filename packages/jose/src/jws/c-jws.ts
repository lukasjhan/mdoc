import * as v from 'valibot';

import type { MaybePromise } from '@protokoll/core';

import { vJwk } from '../jwk/v-jwk.js';
import { vJwtPayload, vJwtVerifyOptions } from '../jwt/index.js';
import { vProtectedHeaderParameters } from '../v-protected-header.js';

export const vJoseJwsJwtVerify = v.object({
  compact: v.string(),
  jwk: vJwk,
  jwtVerifyOptions: v.optional(vJwtVerifyOptions),
});

export const vJoseJwsJwtVerifyOut = v.object({
  payload: vJwtPayload,
  protectedHeader: vProtectedHeaderParameters,
});

export type JoseJwsJwtVerify = (
  input: v.InferInput<typeof vJoseJwsJwtVerify>
) => MaybePromise<v.InferOutput<typeof vJoseJwsJwtVerifyOut>>;

export interface JoseJwsContext {
  jose: {
    jws: { jwtVerify: JoseJwsJwtVerify };
  };
}
