import type { JSONWebKeySet } from '@protokoll/core';
import {
  appendFragmentParams,
  appendQueryParams,
  NOT_IMPLEMENTED,
} from '@protokoll/core';

import type { JarmClientMetadataParams } from '../metadata/v-jarm-client-metadata-params.js';
import type {
  JarmResponseMode,
  Openid4vpJarmResponseMode,
} from '../v-response-mode-registry.js';
import type { ResponseTypeOut } from '../v-response-type-registry.js';
import {
  getJarmDefaultResponseMode,
  validateResponseMode,
} from '../v-response-mode-registry.js';

export interface ClientMetadata {
  jwks?: JSONWebKeySet;
  jwks_uri?: string;
}

export const extractJarmAuthResponseEncJwk = (input: {
  client_metadata: ClientMetadata & JarmClientMetadataParams;
}) => {
  const { client_metadata } = input;

  if (!client_metadata.jwks && !client_metadata.jwks_uri) {
    throw new Error(
      `Invalid client metadata. Neither 'jwks' nor 'jwks_uri' provided. Cannot extract encryption jwk.`
    );
  }

  if (!client_metadata.jwks) {
    throw new Error(
      'Jwk extraction from Remote Json Web Keysets is not yet supported.'
    );
  }

  const encAlg = client_metadata.authorization_encrypted_response_alg;

  const [jwk, ..._rest] = client_metadata.jwks.keys.filter(
    key => key.use === 'enc' && key.alg === encAlg
  );

  if (!jwk) {
    throw new Error(
      `No suitable encryption key found in client_metadata. Expected jwk with use 'enc' and alg '${encAlg}'.`
    );
  }

  return jwk;
};

interface SendJarmAuthResponseInput {
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

  authResponseParams: {
    response: string;
  };
}

export const sendJarmAuthResponse = async (
  input: SendJarmAuthResponseInput
): Promise<Response> => {
  const { authRequestParams, authResponseParams } = input;

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
      return handleDirectPostJwt(responseEndpoint, authResponseParams.response);
    case 'query.jwt':
      return handleQueryJwt(responseEndpoint, authResponseParams.response);
    case 'fragment.jwt':
      return handleFragmentJwt(responseEndpoint, authResponseParams.response);
    case 'form_post.jwt':
      return NOT_IMPLEMENTED('form_post.jwt');
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
