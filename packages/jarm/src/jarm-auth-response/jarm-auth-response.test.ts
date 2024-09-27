import { http, HttpResponse } from 'msw';
import assert from 'node:assert';
import { describe, it } from 'node:test';

import { joseContext } from '@protokoll/jose/dist/src/u-jose-test-context.js';
import { setupServer } from 'msw/node';
import {
  jarmAuthResponseCreate,
  jarmAuthResponseSend,
} from '../jarm-auth-response-send/jarm-auth-response-send.js';
import type { JarmDirectPostJwtAuthResponseValidationContext } from './c-jarm-auth-response.js';
import {
  EXAMPLE_RP_P256_PRIVATE_KEY_JWK,
  ISO_MDL_7_EPHEMERAL_READER_PRIVATE_KEY_JWK,
  ISO_MDL_7_EPHEMERAL_READER_PUBLIC_KEY_JWK,
  ISO_MDL_7_JAR_AUTH_REQUEST_PARAMS,
  ISO_MDL_7_JARM_AUTH_RESPONSE_JWT,
  ISO_MDL_7_JARM_AUTH_RESPONSE_PARAMETERS,
} from './jarm-auth-response.fixtures.js';
import { jarmAuthResponseDirectPostJwtValidate } from './jarm-auth-response.js';

const jarmAuthResponseDirectPostJwtValidationContext: JarmDirectPostJwtAuthResponseValidationContext =
  {
    openid4vp: {
      authRequest: {
        getParams: () => ({
          authRequestParams: ISO_MDL_7_JAR_AUTH_REQUEST_PARAMS,
        }),
      },
    },
    ...joseContext,
    wallet: {
      getJwk: input => {
        if (input.kid === ISO_MDL_7_EPHEMERAL_READER_PRIVATE_KEY_JWK.kid) {
          return { jwk: ISO_MDL_7_EPHEMERAL_READER_PRIVATE_KEY_JWK };
        } else if (input.kid === EXAMPLE_RP_P256_PRIVATE_KEY_JWK.kid) {
          const { d, ...publicKeyJwk } = EXAMPLE_RP_P256_PRIVATE_KEY_JWK;
          return { jwk: publicKeyJwk };
        } else {
          throw new Error('Received jwk with invalid kid.');
        }
      },
    },
  };

void describe('Jarm Auth Response', () => {
  void it(`Create jarmAuthResponse, send JarmAuthRequest, validate JarmAuthResponse (encrypted)`, async () => {
    const authRequestParams = {
      response_type: 'vp_token',
      response_uri: 'https://example-relying-party.com',
      response_mode: 'direct_post.jwt',
    } as const;

    const { authResponse } = await jarmAuthResponseCreate(
      {
        type: 'encrypted',
        encryptionParams: {
          jwk: ISO_MDL_7_EPHEMERAL_READER_PUBLIC_KEY_JWK,
          protectedHeader: {
            alg: ISO_MDL_7_EPHEMERAL_READER_PUBLIC_KEY_JWK.alg,
            kid: ISO_MDL_7_EPHEMERAL_READER_PUBLIC_KEY_JWK.kid,
            enc: 'A256GCM',
          },
        },
        authResponseParams: ISO_MDL_7_JARM_AUTH_RESPONSE_PARAMETERS,
      },
      { ...joseContext }
    );

    const handlers = [
      http.post(`https://example-relying-party.com`, async ({ request }) => {
        const contentType = request.headers.get('Content-Type');
        assert.equal(contentType, 'application/x-www-form-urlencoded');

        // we receive the response we sent
        const receivedAuthResponse = await request.text();
        assert.equal(receivedAuthResponse, authResponse);

        const validatedResponse = await jarmAuthResponseDirectPostJwtValidate(
          { response: authResponse },
          jarmAuthResponseDirectPostJwtValidationContext
        );

        assert.deepEqual(
          ISO_MDL_7_JARM_AUTH_RESPONSE_PARAMETERS,
          validatedResponse.authResponseParams
        );

        assert.deepEqual(validatedResponse.type, 'encrypted');
        return HttpResponse.json({});
      }),
    ];
    const server = setupServer(...handlers);
    server.listen();

    const response = await jarmAuthResponseSend({
      authResponse,
      authRequestParams,
    });

    server.close();
    assert.ok(response.ok);
  });

  void it(`Create jarmAuthResponse, send JarmAuthRequest, validate JarmAuthResponse (signed)`, async () => {
    const authRequestParams = {
      response_type: 'vp_token',
      response_uri: 'https://example-relying-party.com',
      response_mode: 'direct_post.jwt',
    } as const;

    const { authResponse } = await jarmAuthResponseCreate(
      {
        type: 'signed',
        signatureParams: {
          jwk: EXAMPLE_RP_P256_PRIVATE_KEY_JWK,
          protectedHeader: {
            alg: EXAMPLE_RP_P256_PRIVATE_KEY_JWK.alg,
            kid: EXAMPLE_RP_P256_PRIVATE_KEY_JWK.kid,
          },
        },
        authResponseParams: {
          iss: 'https://example-issuer.com',
          aud: 'https://example-relying-party.com',
          exp: 9999999999,
          ...ISO_MDL_7_JARM_AUTH_RESPONSE_PARAMETERS,
        },
      },
      { ...joseContext }
    );

    const handlers = [
      http.post(`https://example-relying-party.com`, async ({ request }) => {
        const contentType = request.headers.get('Content-Type');
        assert.equal(contentType, 'application/x-www-form-urlencoded');

        // we receive the response we sent
        const receivedAuthResponse = await request.text();
        assert.equal(receivedAuthResponse, authResponse);

        const validatedResponse = await jarmAuthResponseDirectPostJwtValidate(
          { response: receivedAuthResponse },
          jarmAuthResponseDirectPostJwtValidationContext
        );

        assert.deepEqual(validatedResponse.type, 'signed');
        return HttpResponse.json({});
      }),
    ];
    const server = setupServer(...handlers);
    server.listen();

    const response = await jarmAuthResponseSend({
      authResponse: authResponse,
      authRequestParams,
    });

    server.close();
    assert.ok(response.ok);
  });

  void it(`Create jarmAuthResponse, send JarmAuthRequest, validate JarmAuthResponse (signed and encrypted)`, async () => {
    const authRequestParams = {
      response_type: 'vp_token',
      response_uri: 'https://example-relying-party.com',
      response_mode: 'direct_post.jwt',
    } as const;

    const { authResponse } = await jarmAuthResponseCreate(
      {
        type: 'signed encrypted',
        signatureParams: {
          jwk: EXAMPLE_RP_P256_PRIVATE_KEY_JWK,
          protectedHeader: {
            alg: EXAMPLE_RP_P256_PRIVATE_KEY_JWK.alg,
            kid: EXAMPLE_RP_P256_PRIVATE_KEY_JWK.kid,
          },
        },
        encryptionParams: {
          jwk: ISO_MDL_7_EPHEMERAL_READER_PUBLIC_KEY_JWK,
          protectedHeader: {
            alg: ISO_MDL_7_EPHEMERAL_READER_PUBLIC_KEY_JWK.alg,
            kid: ISO_MDL_7_EPHEMERAL_READER_PUBLIC_KEY_JWK.kid,
            enc: 'A256GCM',
          },
        },
        authResponseParams: {
          iss: 'https://example-issuer.com',
          aud: 'https://example-relying-party.com',
          exp: 9999999999,
          ...ISO_MDL_7_JARM_AUTH_RESPONSE_PARAMETERS,
        },
      },
      { ...joseContext }
    );

    const handlers = [
      http.post(`https://example-relying-party.com`, async ({ request }) => {
        const contentType = request.headers.get('Content-Type');
        assert.equal(contentType, 'application/x-www-form-urlencoded');

        // we receive the response we sent
        const receivedAuthResponse = await request.text();
        assert.equal(receivedAuthResponse, authResponse);

        const validatedResponse = await jarmAuthResponseDirectPostJwtValidate(
          { response: receivedAuthResponse },
          jarmAuthResponseDirectPostJwtValidationContext
        );
        assert.deepEqual(validatedResponse.type, 'signed encrypted');

        return HttpResponse.json({});
      }),
    ];
    const server = setupServer(...handlers);
    server.listen();

    const response = await jarmAuthResponseSend({
      authResponse: authResponse,
      authRequestParams,
    });

    server.close();
    assert.ok(response.ok);
  });

  void it(`'ISO_MDL_7_JARM_AUTH_RESPONSE' can be validated`, async () => {
    const { authRequestParams, authResponseParams } =
      await jarmAuthResponseDirectPostJwtValidate(
        { response: ISO_MDL_7_JARM_AUTH_RESPONSE_JWT },
        jarmAuthResponseDirectPostJwtValidationContext
      );

    assert.deepEqual(
      ISO_MDL_7_JARM_AUTH_RESPONSE_PARAMETERS,
      authResponseParams
    );
    assert.deepEqual(authRequestParams, authRequestParams);
  });
});
