import assert from 'assert';
import { describe, it } from 'node:test';

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';

import { fetchJWKS } from './u-jose.js';

void describe('u-jose', () => {
  void it('fetchJWKS', async () => {
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

    const jwks = await fetchJWKS('https://example-jwks.com');

    assert.deepStrictEqual(jwks, exampleJwks);
  });
});
