import type { PickDeep } from '@protokoll/core';
import * as v from 'valibot';

import type { JoseContext } from '@protokoll/jose';
import {
  JoseJweEncryptCompact,
  JoseJweEncryptJwt,
  JoseJwsSignJwt,
} from '@protokoll/jose';

import { vJarmAuthResponseEncrypted as vJarmEncryptedOnlyAuthResponse } from '../jarm-auth-response/v-jarm-auth-response-encrypted.js';
import { vJarmAuthResponse } from '../jarm-auth-response/v-jarm-auth-response.js';

export namespace JarmAuthResponseCreate {
  export const vInput = v.variant('type', [
    v.object({
      type: v.literal('signed'),
      authResponse: vJarmAuthResponse,
      jwsSignJwtInput: v.omit(JoseJwsSignJwt.vInput, ['payload']),
    }),
    v.object({
      type: v.literal('encrypted'),
      authResponse: vJarmEncryptedOnlyAuthResponse,
      jweEncryptJwtInput: v.omit(JoseJweEncryptJwt.vInput, ['payload']),
    }),
    v.object({
      type: v.literal('signed encrypted'),
      authResponse: vJarmAuthResponse,
      jwsSignJwtInput: v.omit(JoseJwsSignJwt.vInput, ['payload']),
      jweEncryptCompactInput: v.omit(JoseJweEncryptCompact.vInput, [
        'plaintext',
      ]),
    }),
  ]);
  export type Input = v.InferOutput<typeof vInput>;

  export const vOut = v.object({
    authResponse: v.string(),
  });

  export type Out = v.InferOutput<typeof vOut>;

  export type Context = PickDeep<
    JoseContext,
    'jose.jwe.encryptJwt' | 'jose.jws.signJwt' | 'jose.jwe.encryptCompact'
  >;
}

export const jarmAuthResponseCreate = async (
  input: JarmAuthResponseCreate.Input,
  ctx: JarmAuthResponseCreate.Context
): Promise<JarmAuthResponseCreate.Out> => {
  const { type, authResponse } = input;
  if (input.type === 'encrypted') {
    const { jwe } = await ctx.jose.jwe.encryptJwt({
      ...input.jweEncryptJwtInput,
      payload: authResponse,
    });
    return { authResponse: jwe };
  } else if (type === 'signed') {
    const { jws } = await ctx.jose.jws.signJwt({
      ...input.jwsSignJwtInput,
      payload: authResponse,
    });
    return { authResponse: jws };
  } else {
    const { jws } = await ctx.jose.jws.signJwt({
      ...input.jwsSignJwtInput,
      payload: authResponse,
    });
    const { jwe } = await ctx.jose.jwe.encryptCompact({
      ...input.jweEncryptCompactInput,
      plaintext: jws,
    });

    return { authResponse: jwe };
  }
};
