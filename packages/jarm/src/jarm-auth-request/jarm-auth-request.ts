import {
  appendFragmentParams,
  appendQueryParams,
  NOT_IMPLEMENTED,
} from '@protokoll/core';

import type {
  JwtPayload,
  vJoseJweEncryptJwt,
  vJoseJwsSignJwt,
} from '@protokoll/jose';

import type * as v from 'valibot';
import { JarmError } from '../e-jarm.js';
import type {
  JarmResponseMode,
  Openid4vpJarmResponseMode,
} from '../v-response-mode-registry.js';
import {
  getJarmDefaultResponseMode,
  validateResponseMode,
} from '../v-response-mode-registry.js';
import type { ResponseTypeOut } from '../v-response-type-registry.js';
import type { JarmSendAuthRequestContext as JarmAuthRequestCreateContext } from './c-jarm-auth-request.js';

export type JarmAuthResponseCreate = {
  authResponseParams: JwtPayload;
} & (
  | {
      type: 'signed';
      signatureParams: Omit<v.InferInput<typeof vJoseJwsSignJwt>, 'payload'>;
      encryptionParams?: never;
    }
  | {
      type: 'encrypted';
      signatureParams?: never;
      encryptionParams: Omit<
        v.InferInput<typeof vJoseJweEncryptJwt>,
        'payload'
      >;
    }
  | {
      type: 'signed encrypted';
      signatureParams: Omit<v.InferInput<typeof vJoseJwsSignJwt>, 'payload'>;
      encryptionParams: Omit<
        v.InferInput<typeof vJoseJweEncryptJwt>,
        'payload'
      >;
    }
);

export const jarmAuthResponseCreate = async (
  input: JarmAuthResponseCreate,
  ctx: JarmAuthRequestCreateContext
) => {
  const { type, authResponseParams, signatureParams, encryptionParams } = input;

  if (type === 'encrypted') {
    const { jwe } = await ctx.jose.jwe.encryptJwt({
      ...encryptionParams,
      payload: authResponseParams,
    });
    return { authResponse: jwe };
  } else if (type === 'signed') {
    const { jws } = await ctx.jose.jws.signJwt({
      ...signatureParams,
      payload: authResponseParams,
    });
    return { authResponse: jws };
  } else {
    const { jws } = await ctx.jose.jws.signJwt({
      ...signatureParams,
      payload: authResponseParams,
    });
    const { jwe } = await ctx.jose.jwe.encryptCompact({
      ...encryptionParams,
      plaintext: jws,
    });

    return { authResponse: jwe };
  }
};

interface JarmAuthResponseSend {
  authRequestParams: {
    response_mode?: JarmResponseMode | Openid4vpJarmResponseMode;
    response_type: ResponseTypeOut;
  } & (
    | {
        response_uri: string;
      }
    | {
        redirect_uri: string;
      }
  );

  authResponse: string;
}

export const jarmAuthResponseSend = async (
  input: JarmAuthResponseSend
): Promise<Response> => {
  const { authRequestParams, authResponse } = input;

  const responseEndpoint =
    'response_uri' in authRequestParams
      ? new URL(authRequestParams.response_uri)
      : new URL(authRequestParams.redirect_uri);

  const responseMode =
    authRequestParams.response_mode && authRequestParams.response_mode !== 'jwt'
      ? authRequestParams.response_mode
      : getJarmDefaultResponseMode(authRequestParams);

  validateResponseMode({
    response_type: authRequestParams.response_type,
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
    body: responseJwt,
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
