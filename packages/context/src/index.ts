import { CoseKey, hex, KeyOps, KeyType, MacAlgorithm, type MdocContext, stringToBytes } from '@m-doc/core'
import { p256 } from '@noble/curves/nist.js'
import { hmac } from '@noble/hashes/hmac.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { hkdf } from '@panva/hkdf'
import * as x509 from '@peculiar/x509'
import { exportJWK, importX509 } from 'jose'

/**
 * The slice of WebCrypto this context uses. Declared here rather than pulled
 * from the DOM library, whose `BufferSource` does not accept the
 * `Uint8Array<ArrayBufferLike>` this library passes around.
 */
export type WebCrypto = {
  subtle: { digest(algorithm: string, data: Uint8Array): Promise<ArrayBuffer> }
  getRandomValues<T extends Uint8Array>(array: T): T
}

export type MdocContextOptions = {
  /**
   * The WebCrypto implementation to use. Defaults to `globalThis.crypto`,
   * which Node 20 and every current browser provide. Pass one in where the
   * runtime has no global -- a React Native polyfill, say.
   */
  crypto?: WebCrypto
}

/**
 * An `MdocContext` built on WebCrypto, `@noble/curves` and `@peculiar/x509`.
 *
 * Nothing here is Node-specific: the same implementation runs in the browser
 * and, with a WebCrypto polyfill, in React Native.
 */
export const createMdocContext = (options: MdocContextOptions = {}): MdocContext => {
  const webcrypto = options.crypto ?? (globalThis as { crypto?: WebCrypto }).crypto

  if (!webcrypto?.subtle) {
    throw new Error('No WebCrypto implementation found. Pass one as `crypto` when creating the context.')
  }

  const digest = async (algorithm: string, bytes: Uint8Array) =>
    new Uint8Array(await webcrypto.subtle.digest(algorithm, bytes))

  return {
    crypto: {
      digest: async ({ digestAlgorithm, bytes }) => digest(digestAlgorithm, bytes),

      random: (length: number) => webcrypto.getRandomValues(new Uint8Array(length)),

      calculateEphemeralMacKey: async ({ privateKey, publicKey, sessionTranscriptBytes, info }) => {
        const ikm = p256.getSharedSecret(privateKey, publicKey, true).slice(1)
        const salt = await digest('SHA-256', sessionTranscriptBytes)
        const key = await hkdf('sha256', ikm, salt, stringToBytes(info), 32)

        return new CoseKey({
          keyOps: [KeyOps.Sign, KeyOps.Verify],
          keyType: KeyType.Oct,
          k: key,
          algorithm: MacAlgorithm.HS256,
        })
      },
    },

    cose: {
      mac0: {
        sign: async ({ key, mac0 }) => hmac(sha256, key.privateKey, mac0.toBeAuthenticated),

        verify: async ({ mac0, key }) => {
          if (!mac0.tag) throw new Error('tag is required for mac0 verification')

          return mac0.tag === hmac(sha256, key.privateKey, mac0.toBeAuthenticated)
        },
      },

      sign1: {
        sign: async ({ key, sign1 }) => p256.sign(sign1.toBeSigned, key.privateKey, { format: 'compact' }),

        verify: async ({ sign1, key }) => {
          const { toBeSigned, signature } = sign1

          if (!signature) throw new Error('signature is required for sign1 verification')

          // lowS off: signatures in the wild are not all canonical
          return p256.verify(signature, toBeSigned, key.publicKey, { lowS: false })
        },
      },
    },

    x509: {
      getIssuerNameField: ({ certificate, field }) => new x509.X509Certificate(certificate).issuerName.getField(field),

      getPublicKey: async ({ certificate, alg }) => {
        const parsed = new x509.X509Certificate(certificate)
        const key = await importX509(parsed.toString(), alg, { extractable: true })

        return CoseKey.fromJwk((await exportJWK(key)) as unknown as Record<string, unknown>)
      },

      verifyCertificateChain: async ({ trustedCertificates, x5chain, now }) => {
        if (x5chain.length === 0) throw new Error('Certificate chain is empty')

        const leaf = new x509.X509Certificate(x5chain[0])
        const presented = x5chain.map((c) => new x509.X509Certificate(c))
        const trusted = trustedCertificates.map((c) => new x509.X509Certificate(c))

        const builder = new x509.X509ChainBuilder({ certificates: [...presented, ...trusted] })
        const built = await builder.build(leaf)

        // x5chain puts the leaf first; @peculiar/x509 wants it last
        let chain = built.map((c) => new x509.X509Certificate(c.rawData)).reverse()

        // A longer chain is fine: the root may be trusted without being presented
        if (chain.length < x5chain.length) {
          throw new Error('Could not parse the full chain. Likely due to incorrect ordering')
        }

        const trustedIndex = chain.findIndex((cert) => trusted.some((t) => cert.equal(t)))

        if (trustedIndex === -1) {
          throw new Error('No trusted certificate was found while validating the X.509 chain')
        }

        // FIXME: verifying against a trusted *leaf* degenerates to an equality
        // check, which skips the validity period. Trust anchors should be roots.
        chain = chain.slice(0, trustedIndex)

        for (let i = 0; i < chain.length; i++) {
          const certificate = chain[i]
          const issuer = chain[i - 1]

          await certificate?.verify({ publicKey: issuer ? issuer.publicKey : undefined, date: now ?? new Date() })
        }
      },

      getCertificateData: async ({ certificate }) => {
        const parsed = new x509.X509Certificate(certificate)

        return {
          issuerName: parsed.issuerName.toString(),
          subjectName: parsed.subjectName.toString(),
          pem: parsed.toString(),
          serialNumber: parsed.serialNumber,
          thumbprint: hex.encode(new Uint8Array(await parsed.getThumbprint())),
          notBefore: parsed.notBefore,
          notAfter: parsed.notAfter,
        }
      },
    },
  }
}
