import * as v from 'valibot';

import type { MaybePromise } from '@protokoll/core';

import { vJwk } from '../jwk/v-jwk.js';
import { vJwtPayload } from '../jwt/v-jwt.js';
import { vCompactJweHeader } from './v-jwe.js';

export const vJoseJweDecryptCompactInput = v.object({
  jwe: v.string(),
  jwk: vJwk,
});
export const vJoseJweDecryptCompactOut = v.object({
  plaintext: v.string(),
  protectedHeader: vCompactJweHeader,
});
export type JoseJweDecryptCompact = (
  input: v.InferInput<typeof vJoseJweDecryptCompactInput>
) => MaybePromise<v.InferOutput<typeof vJoseJweDecryptCompactOut>>;

export const vJoseJweEncryptCompactInput = v.object({
  plaintext: v.string(),
  jwk: vJwk,
  protectedHeader: vCompactJweHeader,
  alg: v.optional(v.string()),
  keyManagement: v.optional(v.object({ apu: v.string(), apv: v.string() })),
});
export const vJoseJweEncryptCompactOut = v.object({ jwe: v.string() });
export type JoseJweEncryptCompact = (
  input: v.InferInput<typeof vJoseJweEncryptCompactInput>
) => MaybePromise<v.InferOutput<typeof vJoseJweEncryptCompactOut>>;

export const vJoseJweEncryptJwtInput = v.object({
  payload: vJwtPayload,
  protectedHeader: vCompactJweHeader,
  jwk: vJwk,
  alg: v.optional(v.string()),
  keyManagement: v.optional(v.object({ apu: v.string(), apv: v.string() })),
});
export const vJoseJweEncryptJwtOut = v.object({ jwe: v.string() });
export type JoseJweEncryptJwt = (
  input: v.InferInput<typeof vJoseJweEncryptJwtInput>
) => MaybePromise<v.InferOutput<typeof vJoseJweEncryptJwtOut>>;

export const vJoseJweDecryptJwtInput = v.object({
  jwe: v.string(),
  jwk: vJwk,
});
export const vJoseJweDecryptJwtOut = v.object({
  payload: vJwtPayload,
  protectedHeader: vCompactJweHeader,
});
export type JoseJweDecryptJwt = (
  input: v.InferInput<typeof vJoseJweDecryptJwtInput>
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
