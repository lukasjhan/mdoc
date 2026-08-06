import {
  CoseKey,
  DeviceRequest,
  DeviceResponse,
  DocRequest,
  Holder,
  Issuer,
  IssuerSigned,
  ItemsRequest,
  SessionTranscript,
  SignatureAlgorithm,
} from '@m-doc/core'
import * as x509 from '@peculiar/x509'
import { describe, expect, it } from 'vitest'
import { createMdocContext } from '../src'

const ctx = createMdocContext()

x509.cryptoProvider.set(globalThis.crypto)

const generateKeyPair = async () => {
  const keys = await globalThis.crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, [
    'sign',
    'verify',
  ])
  const privateJwk = (await globalThis.crypto.subtle.exportKey('jwk', keys.privateKey)) as Record<string, unknown>
  const withAlg: Record<string, unknown> = { ...privateJwk, alg: 'ES256' }
  const { d: _d, ...publicJwk } = withAlg

  return {
    keys,
    privateKey: CoseKey.fromJwk(withAlg),
    publicKey: CoseKey.fromJwk(publicJwk),
  }
}

/**
 * The whole round trip against this context: an issuer signs a document, a
 * holder presents part of it, and a verifier checks what came back. It is what
 * the playground does, and what a wallet does.
 */
describe('issue, present, verify', () => {
  it('round-trips an mDL through a selective disclosure', async () => {
    const issuer = await generateKeyPair()
    const device = await generateKeyPair()

    const certificate = await x509.X509CertificateGenerator.createSelfSigned({
      serialNumber: '01',
      name: 'CN=test issuer, C=NL',
      notBefore: new Date(Date.now() - 60_000),
      notAfter: new Date(Date.now() + 86_400_000),
      signingAlgorithm: { name: 'ECDSA', hash: 'SHA-256' },
      keys: issuer.keys,
      extensions: [new x509.BasicConstraintsExtension(true, 0, true)],
    })
    const certificateBytes = new Uint8Array(certificate.rawData)

    const validFrom = new Date()
    const validUntil = new Date(Date.now() + 86_400_000)

    const issuerSigned = await new Issuer('org.iso.18013.5.1.mDL', ctx)
      .addIssuerNamespace('org.iso.18013.5.1', {
        family_name: 'Han',
        given_name: 'Lukas',
        age_over_18: true,
        document_number: 'NL-000123',
      })
      .sign({
        signingKey: issuer.privateKey,
        certificate: certificateBytes,
        algorithm: SignatureAlgorithm.ES256,
        digestAlgorithm: 'SHA-256',
        deviceKeyInfo: { deviceKey: device.publicKey },
        validityInfo: { signed: validFrom, validFrom, validUntil },
      })

    // The holder verifies what it was issued before storing it
    await expect(
      Holder.verifyIssuerSigned({ issuerSigned, trustedCertificates: [certificateBytes] }, ctx)
    ).resolves.toBeUndefined()

    const sessionTranscript = await SessionTranscript.forOid4Vp(
      {
        clientId: 'x509_san_dns:verifier.example.com',
        responseUri: 'https://verifier.example.com/response',
        nonce: 'n-0S6_WzA2Mj',
      },
      ctx
    )

    // The verifier asks for two of the four elements
    const deviceRequest = new DeviceRequest({
      docRequests: [
        new DocRequest({
          itemsRequest: new ItemsRequest({
            docType: 'org.iso.18013.5.1.mDL',
            namespaces: { 'org.iso.18013.5.1': { family_name: false, age_over_18: false } },
          }),
        }),
      ],
    })

    const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
      {
        deviceRequest,
        sessionTranscript,
        issuerSigned: [IssuerSigned.decode(issuerSigned.encode())],
        signature: { signingKey: device.privateKey },
      },
      ctx
    )

    const received = DeviceResponse.decode(deviceResponse.encode())

    await expect(
      received.verify({ trustedCertificates: [certificateBytes], sessionTranscript, deviceRequest }, ctx)
    ).resolves.toBeUndefined()

    const claims = received.getAllPrettyClaims()['org.iso.18013.5.1.mDL']['org.iso.18013.5.1']

    expect(claims).toEqual({ family_name: 'Han', age_over_18: true })
    // The elements that were not asked for stayed behind
    expect(claims.given_name).toBeUndefined()
    expect(claims.document_number).toBeUndefined()
  })
})
