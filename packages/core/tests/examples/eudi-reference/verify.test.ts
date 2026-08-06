import { X509Certificate } from '@peculiar/x509'
import { describe, expect, test } from 'vitest'
import { DeviceResponse, hex, SessionTranscript, StatusListInfo } from '../../../src'
import { mdocContext } from '../../context'
import { deviceResponse } from './deviceResponse'
import { issuerCertificate } from './issuerCertificate'

describe('EUDI Wallet Reference Implementation', () => {
  const clientId = 'x509_san_dns:eudi-verifier.dev.hopae.app'
  const responseUri = 'https://eudi-verifier.dev.hopae.app/openid4vp/response/7029722b-6a19-4031-8570-681fe4c749a7'
  const nonce = '1d9fc138-ffdc-48a2-a59a-96118b768f8c'

  // RFC 7638 thumbprint of the verifier's ECDH-ES encryption key; the response
  // mode was direct_post.jwt, so it is part of the handover.
  const jwkThumbprint = Buffer.from('a127f2346cb0fe83ab65cb872566bb5e44ec3f6de7fd54437e81eb9501edaa7b', 'hex')

  const sessionTranscript = () =>
    SessionTranscript.forOid4Vp({ clientId, responseUri, nonce, jwkThumbprint }, mdocContext)

  test('verify PID DeviceResponse (OpenID4VP 1.0, direct_post.jwt)', async () => {
    await expect(
      DeviceResponse.decode(deviceResponse).verify(
        {
          trustedCertificates: [new Uint8Array(new X509Certificate(issuerCertificate).rawData)],
          sessionTranscript: await sessionTranscript(),
          now: new Date('2026-03-01'),
        },
        mdocContext
      )
    ).resolves.toBeUndefined()
  })

  test('exposes the disclosed claims', () => {
    const document = DeviceResponse.decode(deviceResponse).documents?.[0]

    expect(document?.docType).toBe('eu.europa.ec.eudi.pid.1')
    expect(document?.issuerSigned.getPrettyClaims('eu.europa.ec.eudi.pid.1')).toMatchObject({
      family_name: 'Han',
      given_name: 'Lukas',
      nationality: ['LU'],
    })
  })

  test('reads status_list and keeps identifier_list alongside it', () => {
    const document = DeviceResponse.decode(deviceResponse).documents?.[0]
    const status = document?.issuerSigned.issuerAuth.mobileSecurityObject.status

    expect(status?.statusList).toBeInstanceOf(StatusListInfo)
    expect(status?.statusList?.idx).toBe(9404)
    expect(status?.statusList?.uri).toContain('issuer.eudiw.dev/token_status_list/')

    // Not modelled, so it has to come through the schema untouched
    const identifierList = status?.additional.get('identifier_list') as Map<string, unknown>
    expect(identifierList.get('id')).toBe('9404')
    expect(identifierList.get('uri')).toContain('issuer.eudiw.dev/identifier_list/')
  })

  test('re-encodes the MSO to the bytes the signature covers', () => {
    const { issuerAuth } = DeviceResponse.decode(deviceResponse).documents?.[0].issuerSigned ?? {}
    const received = issuerAuth?.payload as Uint8Array

    expect(hex.encode(issuerAuth?.mobileSecurityObject.encode({ asDataItem: true }) as Uint8Array)).toBe(
      hex.encode(received)
    )
  })
})
