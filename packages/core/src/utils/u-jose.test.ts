import assert from 'assert';
import { describe, it } from 'node:test';

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';

import { joseFetchJWKS } from './u-jose.js';

void describe('u-jose', () => {
  void it('fetchJWKS should return the jwks', async () => {
    const exampleJwks = {
      keys: [
        {
          kid: 'kid',
          kty: 'EC',
        },
      ],
    };

    const handlers = [
      http.get(`https://example-jwks.com`, ({ request }) => {
        const accept = request.headers.get('accept');
        assert.equal(accept, 'application/json');

        return HttpResponse.json(exampleJwks);
      }),
    ];
    const server = setupServer(...handlers);
    server.listen();

    const jwks = await joseFetchJWKS('https://example-jwks.com');
    server.close();

    assert.deepStrictEqual(jwks, exampleJwks);
  });

  void it('fetchJWKS should return undefined if the jwks is empty', async () => {
    const exampleJwks = {
      keys: [],
    };

    const handlers = [
      http.get(`https://example-jwks.com`, ({ request }) => {
        const accept = request.headers.get('accept');
        assert.equal(accept, 'application/json');

        return HttpResponse.json(exampleJwks);
      }),
    ];
    const server = setupServer(...handlers);
    server.listen();

    const jwks = await joseFetchJWKS('https://example-jwks.com');
    server.close();

    assert.deepStrictEqual(jwks, undefined);
  });
});
