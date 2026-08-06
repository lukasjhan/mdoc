/**
 * Enough of an `MdocContext` to check one COSE_Sign1, built on Node's own
 * primitives: `node:crypto` parses the signer certificate and WebCrypto
 * verifies ECDSA over the Sig_structure.
 *
 * This is what lets the CLI check a signature while the package still depends
 * on nothing but `@m-doc/core` and `zod`. A COSE signature is raw r||s, which
 * is the format WebCrypto wants, so no re-encoding is needed.
 *
 * Node-only, and deliberately not exported from the package entry: importing
 * `node:crypto` would break the browser build. Reach for `@m-doc/context` in
 * an application -- it covers signing, MACs and chain validation too.
 */

import { type JsonWebKey, X509Certificate } from 'node:crypto'
import { CoseKey, type MdocContext } from '@m-doc/core'

const HASH_FOR_CURVE = { 'P-256': 'SHA-256', 'P-384': 'SHA-384', 'P-521': 'SHA-512' } as const

type Curve = keyof typeof HASH_FOR_CURVE

const unsupported = (what: string) => () => {
  throw new Error(`${what} is not available in the verify-only context`)
}

export const nodeVerificationContext: Pick<MdocContext, 'cose' | 'x509'> = {
  x509: {
    getPublicKey: ({ certificate }) =>
      CoseKey.fromJwk(new X509Certificate(certificate).publicKey.export({ format: 'jwk' }) as Record<string, unknown>),

    getIssuerNameField: unsupported('reading an issuer name'),
    verifyCertificateChain: unsupported('chain validation'),
    getCertificateData: unsupported('reading certificate data'),
  },

  cose: {
    sign1: {
      verify: async ({ sign1, key }) => {
        if (!sign1.signature) return false

        const jwk = key.jwk as { crv?: Curve }
        const curve = jwk.crv ?? 'P-256'
        const hash = HASH_FOR_CURVE[curve]

        if (!hash) throw new Error(`Unsupported curve: ${curve}`)

        const imported = await crypto.subtle.importKey(
          'jwk',
          { ...jwk, ext: true, key_ops: ['verify'] } as JsonWebKey,
          { name: 'ECDSA', namedCurve: curve },
          true,
          ['verify']
        )

        return crypto.subtle.verify({ name: 'ECDSA', hash }, imported, sign1.signature, sign1.toBeSigned)
      },

      sign: unsupported('signing'),
    },

    mac0: {
      sign: unsupported('signing'),
      verify: unsupported('MAC verification'),
    },
  },
}
