import * as v from 'valibot';

import type { MaybePromise } from '@protokoll/core';

import { vJwk } from '../jwk/v-jwk.js';
import { vJwtPayload } from '../jwt/v-jwt.js';
import { vCompactJweHeaderParameters } from './v-jwe.js';

export const vJoseJweDecryptCompact = v.object({
  jwe: v.string(),
  jwk: vJwk,
});
export const vJoseJweDecryptCompactOut = v.object({
  plaintext: v.string(),
  protectedHeader: vCompactJweHeaderParameters,
});
export type JoseJweDecryptCompact = (
  input: v.InferInput<typeof vJoseJweDecryptCompact>
) => MaybePromise<v.InferOutput<typeof vJoseJweDecryptCompactOut>>;

export const vJoseJweEncryptCompact = v.object({
  plaintext: v.string(),
  jwk: vJwk,
  protectedHeader: vCompactJweHeaderParameters,
  alg: v.optional(v.string()),
  keyManagementParameters: v.optional(
    v.object({ apu: v.string(), apv: v.string() })
  ),
});
export const vJoseJweEncryptCompactOut = v.object({ jwe: v.string() });
export type JoseJweEncryptCompact = (
  input: v.InferInput<typeof vJoseJweEncryptCompact>
) => MaybePromise<v.InferOutput<typeof vJoseJweEncryptCompactOut>>;

export const vJoseJweEncryptJwt = v.object({
  payload: vJwtPayload,
  protectedHeader: vCompactJweHeaderParameters,
  jwk: vJwk,
  alg: v.optional(v.string()),
  keyManagementParameters: v.optional(
    v.object({ apu: v.string(), apv: v.string() })
  ),
});
export const vJoseJweEncryptJwtOut = v.object({ jwe: v.string() });
export type JoseJweEncryptJwt = (
  input: v.InferInput<typeof vJoseJweEncryptJwt>
) => MaybePromise<v.InferOutput<typeof vJoseJweEncryptJwtOut>>;

export const vJoseJweDecryptJwt = v.object({
  jwe: v.string(),
  jwk: vJwk,
});
export const vJoseJweDecryptJwtOut = v.object({
  payload: vJwtPayload,
  protectedHeader: vCompactJweHeaderParameters,
});
export type JoseJweDecryptJwt = (
  input: v.InferInput<typeof vJoseJweDecryptJwt>
) => MaybePromise<v.InferOutput<typeof vJoseJweDecryptJwtOut>>;

export interface JoseJweContext {
  jose: {
    jwe: {
      decryptCompact: JoseJweDecryptCompact;
      encryptCompact: JoseJweEncryptCompact;
      encryptJwt: JoseJweEncryptJwt;
      decryptJwt: JoseJweDecryptJwt;
    };
  };
}
