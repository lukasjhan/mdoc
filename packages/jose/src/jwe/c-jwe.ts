import * as v from 'valibot';

import type { MaybePromise } from '@protokoll/core';

import { vJwk } from '../jwk/v-jwk.js';
import { vJwtPayload } from '../jwt/v-jwt.js';
import { vCompactJweHeader } from './v-jwe.js';

export namespace JoseJweDecryptCompact {
  export const vInput = v.object({
    jwe: v.string(),
    jwk: vJwk,
  });
  export type Input = v.InferInput<typeof vInput>;

  export const vOut = v.object({
    plaintext: v.string(),
    protectedHeader: vCompactJweHeader,
  });
  export type Out = v.InferOutput<typeof vOut>;
}

export type JoseJweDecryptCompact = (
  input: JoseJweDecryptCompact.Input
) => MaybePromise<JoseJweDecryptCompact.Out>;

export namespace JoseJweEncryptCompact {
  export const vInput = v.object({
    plaintext: v.string(),
    jwk: vJwk,
    protectedHeader: vCompactJweHeader,
    alg: v.optional(v.string()),
    keyManagement: v.optional(v.object({ apu: v.string(), apv: v.string() })),
  });
  export type Input = v.InferInput<typeof vInput>;

  export const vOut = v.object({ jwe: v.string() });
  export type Out = v.InferOutput<typeof vOut>;
}
export type JoseJweEncryptCompact = (
  input: JoseJweEncryptCompact.Input
) => MaybePromise<JoseJweEncryptCompact.Out>;

export namespace JoseJweEncryptJwt {
  export const vInput = v.object({
    payload: vJwtPayload,
    protectedHeader: vCompactJweHeader,
    jwk: vJwk,
    alg: v.optional(v.string()),
    keyManagement: v.optional(v.object({ apu: v.string(), apv: v.string() })),
  });
  export type Input = v.InferInput<typeof vInput>;

  export const vOut = v.object({ jwe: v.string() });
  export type Out = v.InferOutput<typeof vOut>;
}
export type JoseJweEncryptJwt = (
  input: JoseJweEncryptJwt.Input
) => MaybePromise<JoseJweEncryptJwt.Out>;

export namespace JoseJweDecryptJwt {
  export const vInput = v.object({
    jwe: v.string(),
    jwk: vJwk,
  });
  export type Input = v.InferInput<typeof vInput>;

  export const vOut = v.object({
    payload: vJwtPayload,
    protectedHeader: vCompactJweHeader,
  });
  export type Out = v.InferOutput<typeof vOut>;
}

export type JoseJweDecryptJwt = (
  input: JoseJweDecryptJwt.Input
) => MaybePromise<JoseJweDecryptJwt.Out>;

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
