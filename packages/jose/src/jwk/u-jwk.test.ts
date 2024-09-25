import assert from 'assert';
import { describe, it } from 'node:test';

import { http, HttpResponse } from 'msw';
import { setupServer } from 'msw/node';

import { joseJwksFetch } from './u-jwk.js';

void describe('u-jwk', () => {
  void it('joseJwksFetch should return the jwks', async () => {
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

    const jwks = await joseJwksFetch('https://example-jwks.com');
    server.close();

    assert.deepStrictEqual(jwks, exampleJwks);
  });

  void it('joseJwksFetch should return undefined if the jwks is empty', async () => {
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

    const jwks = await joseJwksFetch('https://example-jwks.com');
    server.close();

    assert.deepStrictEqual(jwks, undefined);
  });
});
