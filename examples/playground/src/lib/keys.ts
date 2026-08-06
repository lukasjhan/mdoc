import { CoseKey, SignatureAlgorithm } from '@m-doc/core'
import * as x509 from '@peculiar/x509'

export type GeneratedIssuer = {
  signingKey: CoseKey
  certificate: Uint8Array
  certificatePem: string
}

const crypto = globalThis.crypto

x509.cryptoProvider.set(crypto)

const toJwk = async (key: CryptoKey) => (await crypto.subtle.exportKey('jwk', key)) as Record<string, unknown>

/**
 * A P-256 key pair with a self-signed certificate, for signing documents in the
 * playground.
 *
 * A real issuer's key sits behind an HSM and its certificate chains to an IACA
 * root a verifier already trusts. Nothing signed here is trustworthy to anyone
 * else — the point is to have something to decode.
 */
export const generateIssuer = async (commonName = 'mdoc playground'): Promise<GeneratedIssuer> => {
  const algorithm = { name: 'ECDSA', namedCurve: 'P-256' } as const
  const keys = await crypto.subtle.generateKey(algorithm, true, ['sign', 'verify'])

  const certificate = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: `CN=${commonName}, C=NL`,
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000),
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    keys,
    extensions: [new x509.BasicConstraintsExtension(true, 0, true)],
  })

  return {
    signingKey: CoseKey.fromJwk({ ...(await toJwk(keys.privateKey)), alg: 'ES256' }),
    certificate: new Uint8Array(certificate.rawData),
    certificatePem: certificate.toString('pem'),
  }
}

/** A P-256 key pair for the holder's device binding. */
export const generateDeviceKey = async (): Promise<{ privateKey: CoseKey; publicKey: CoseKey }> => {
  const keys = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])

  const privateJwk: Record<string, unknown> = { ...(await toJwk(keys.privateKey)), alg: 'ES256' }
  const { d: _d, ...publicJwk } = privateJwk

  return {
    privateKey: CoseKey.fromJwk(privateJwk),
    publicKey: CoseKey.fromJwk(publicJwk),
  }
}

export const ES256 = SignatureAlgorithm.ES256
