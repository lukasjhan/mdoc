import { describe, expect, it } from 'vitest'
import { DeviceResponse, SessionTranscript } from '../../../src'
import { mdocContext } from '../../context'
import { deviceResponse } from './deviceResponse'
import { issuerCertificate } from './issuerCertificate'

/**
 * The French playground's mdoc, presented over ISO/IEC TS 18013-7:2025 Annex B
 * (OpenID4VP draft 18).
 *
 * It sends an empty `mdocGeneratedNonce`, which B.4.4 allows -- it types the
 * field as a tstr, and an empty tstr is one. This test used to assert that
 * verification threw, which it did, but for the wrong reason: the handover
 * checked the nonce for truthiness and so refused to hash at all. With that
 * fixed, the vector verifies in full.
 */
describe('French playground mdoc implementation', () => {
  it('verifies a DeviceResponse presented with an empty mdocGeneratedNonce', async () => {
    await expect(
      DeviceResponse.decode(deviceResponse).verify(
        {
          trustedCertificates: [new Uint8Array(issuerCertificate.rawData)],
          sessionTranscript: await SessionTranscript.forOid4VpDraft18(
            {
              clientId: 'example.com',
              responseUri: 'https://example.com/12345/response',
              verifierGeneratedNonce: 'abcdefgh1234567890',
              mdocGeneratedNonce: '',
            },
            mdocContext
          ),
          now: new Date('2021-09-25'),
        },
        mdocContext
      )
    ).resolves.toBeUndefined()
  })
})
