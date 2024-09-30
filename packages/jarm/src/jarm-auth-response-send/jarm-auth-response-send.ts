import {
  appendFragmentParams,
  appendQueryParams,
  NOT_IMPLEMENTED,
} from '@protokoll/core';
import * as v from 'valibot';

import { vJwe, vJws } from '@protokoll/jose';

import { JarmError } from '../e-jarm.js';
import {
  getJarmDefaultResponseMode,
  validateResponseMode,
  vJarmResponseMode,
  vOpenid4vpJarmResponseMode,
} from '../v-response-mode-registry.js';
import { vResponseType } from '../v-response-type-registry.js';

export namespace JarmAuthResponseSend {
  export const vInput = v.object({
    authRequest: v.intersect([
      v.object({
        response_mode: v.optional(
          v.union([vJarmResponseMode, vOpenid4vpJarmResponseMode])
        ),
        response_type: vResponseType,
      }),
      v.union([
        v.object({
          response_uri: v.string(),
          redirect_uri: v.optional(v.never()),
        }),
        v.object({
          response_uri: v.optional(v.never()),
          redirect_uri: v.string(),
        }),
      ]),
    ]),
    authResponse: v.union([vJwe, vJws]),
  });
  export type Input = v.InferOutput<typeof vInput>;

  export type Out = Response;
}

export const jarmAuthResponseSend = async (
  input: JarmAuthResponseSend.Input
): Promise<JarmAuthResponseSend.Out> => {
  const { authRequest, authResponse } = input;

  const responseEndpoint = authRequest.response_uri ?? authRequest.redirect_uri;
  const responseEndpointUrl = new URL(responseEndpoint);

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
      return handleDirectPostJwt(responseEndpointUrl, authResponse);
    case 'query.jwt':
      return handleQueryJwt(responseEndpointUrl, authResponse);
    case 'fragment.jwt':
      return handleFragmentJwt(responseEndpointUrl, authResponse);
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
