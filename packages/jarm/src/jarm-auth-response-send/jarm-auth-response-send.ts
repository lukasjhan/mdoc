import {
  appendFragmentParams,
  appendQueryParams,
  NOT_IMPLEMENTED,
} from '@protokoll/core';
import * as v from 'valibot';

import {
  vJoseJweEncryptCompactInput,
  vJoseJweEncryptJwtInput,
  vJoseJwsSignJwtInput,
  vJwe,
  vJws,
} from '@protokoll/jose';

import { JarmError } from '../e-jarm.js';
import { vJarmAuthResponse } from '../jarm-auth-response/v-jarm-auth-response';
import { vJarmEncrytedOnlyAuthResponse as vJarmEncryptedOnlyAuthResponse } from '../jarm-auth-response/v-jarm-direct-post-jwt-auth-response.js';
import {
  getJarmDefaultResponseMode,
  validateResponseMode,
  vJarmResponseMode,
  vOpenid4vpJarmResponseMode,
} from '../v-response-mode-registry.js';
import { vResponseType } from '../v-response-type-registry.js';
import type { JarmAuthResponseCreateContext } from './c-jarm-auth-response-send.js';

export const vJarmAuthResponseCreateInput = v.variant('type', [
  v.object({
    type: v.literal('signed'),
    authResponse: vJarmAuthResponse,
    jwsSignJwtInput: v.omit(vJoseJwsSignJwtInput, ['payload']),
  }),
  v.object({
    type: v.literal('encrypted'),
    authResponse: vJarmEncryptedOnlyAuthResponse,
    jweEncryptJwtInput: v.omit(vJoseJweEncryptJwtInput, ['payload']),
  }),
  v.object({
    type: v.literal('signed encrypted'),
    authResponse: vJarmAuthResponse,
    jwsSignJwtInput: v.omit(vJoseJwsSignJwtInput, ['payload']),
    jweEncryptCompactInput: v.omit(vJoseJweEncryptCompactInput, ['plaintext']),
  }),
]);

export type JarmAuthResponseCreateInput = v.InferOutput<
  typeof vJarmAuthResponseCreateInput
>;

export const jarmAuthResponseCreate = async (
  input: JarmAuthResponseCreateInput,
  ctx: JarmAuthResponseCreateContext
) => {
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

export const vJarmAuthResponseSendInput = v.object({
  authRequest: v.intersect([
    v.object({
      response_mode: v.optional(
        v.union([vJarmResponseMode, vOpenid4vpJarmResponseMode])
      ),
      response_type: vResponseType,
    }),
    v.union([
      v.looseObject({
        response_uri: v.string(),
        redirect_uri: v.optional(v.never()),
      }),
      v.looseObject({
        redirect_uri: v.string(),
        response_uri: v.optional(v.never()),
      }),
    ]),
  ]),
  authResponse: v.union([vJwe, vJws]),
});
export type JarmAuthResponseSendInput = v.InferOutput<
  typeof vJarmAuthResponseSendInput
>;

export const jarmAuthResponseSend = async (
  input: JarmAuthResponseSendInput
): Promise<Response> => {
  const { authRequest, authResponse } = input;

  const responseEndpoint = authRequest.response_uri
    ? new URL(authRequest.response_uri)
    : // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
      new URL(authRequest.redirect_uri!);

  const responseMode =
    authRequest.response_mode && authRequest.response_mode !== 'jwt'
      ? authRequest.response_mode
      : getJarmDefaultResponseMode(authRequest);

  validateResponseMode({
    response_type: authRequest.response_type,
    response_mode: responseMode,
  });

  switch (responseMode) {
    case 'direct_post.jwt':
      return handleDirectPostJwt(responseEndpoint, authResponse);
    case 'query.jwt':
      return handleQueryJwt(responseEndpoint, authResponse);
    case 'fragment.jwt':
      return handleFragmentJwt(responseEndpoint, authResponse);
    case 'form_post.jwt':
      return NOT_IMPLEMENTED({
        message: 'form_post.jwt',
        error: JarmError,
      });
  }
};

async function handleDirectPostJwt(responseEndpoint: URL, responseJwt: string) {
  const response = await fetch(responseEndpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `response=${responseJwt}`,
  });

  return response;
}

async function handleQueryJwt(responseEndpoint: URL, responseJwt: string) {
  const responseUrl = appendQueryParams({
    url: responseEndpoint,
    params: { response: responseJwt },
  });

  const response = await fetch(responseUrl, { method: 'POST' });
  return response;
}

async function handleFragmentJwt(responseEndpoint: URL, responseJwt: string) {
  const responseUrl = appendFragmentParams({
    url: responseEndpoint,
    fragments: { response: responseJwt },
  });
  const response = await fetch(responseUrl, { method: 'POST' });
  return response;
}
