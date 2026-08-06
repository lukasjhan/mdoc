/**
 * The setup every example needs: a context, a key pair, and a certificate.
 *
 * None of this is mdoc-specific — it is the X.509 and key handling any issuer
 * has to do already, kept out of the examples so they stay about the format.
 */

import type { webcrypto } from 'node:crypto'
import { createMdocContext } from '@m-doc/context'
import { CoseKey } from '@m-doc/core'
import * as x509 from '@peculiar/x509'

/** `@m-doc/core` does no cryptography itself; this binds it to WebCrypto. */
export const ctx = createMdocContext()

x509.cryptoProvider.set(globalThis.crypto)

export type KeyPair = {
  /** The WebCrypto pair, for `@peculiar/x509` to sign a certificate with. */
  keys: webcrypto.CryptoKeyPair
  privateKey: CoseKey
  publicKey: CoseKey
}

export const generateKeyPair = async (): Promise<KeyPair> => {
  const keys = await globalThis.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])

  const privateJwk = (await globalThis.crypto.subtle.exportKey('jwk', keys.privateKey)) as Record<string, unknown>
  const withAlg: Record<string, unknown> = { ...privateJwk, alg: 'ES256' }
  const { d: _private, ...publicJwk } = withAlg

  return { keys, privateKey: CoseKey.fromJwk(withAlg), publicKey: CoseKey.fromJwk(publicJwk) }
}

/**
 * A self-signed certificate, standing in for the document signer a real issuer
 * would have been given by its IACA. Good enough to decode and verify against
 * itself; trusted by nobody.
 */
export const createCertificate = async (options: {
  keys: webcrypto.CryptoKeyPair
  name?: string
  validForDays?: number
}): Promise<Uint8Array> => {
  const certificate = await x509.X509CertificateGenerator.createSelfSigned({
    serialNumber: '01',
    name: options.name ?? 'CN=Example Issuer, C=NL',
    notBefore: new Date(Date.now() - 60_000),
    notAfter: new Date(Date.now() + (options.validForDays ?? 365) * 86_400_000),
    signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
    keys: options.keys,
    extensions: [new x509.BasicConstraintsExtension(true, 0, true)],
  })

  return new Uint8Array(certificate.rawData)
}

export const heading = (text: string) => console.log(`\n\x1b[1m${text}\x1b[0m`)

export const field = (label: string, value: unknown) => console.log(`  ${label.padEnd(22)} ${String(value)}`)

export const truncate = (value: string, length = 72) =>
  value.length > length ? `${value.slice(0, length)}… (${value.length} chars)` : value

/**
 * Runs an example. tsx compiles these as CommonJS -- the workspace packages
 * resolve to TypeScript sources rather than to built ESM -- so there is no
 * top-level await to lean on.
 */
export const run = (main: () => Promise<void>) => {
  main().catch((error) => {
    console.error(error)
    process.exit(1)
  })
}
