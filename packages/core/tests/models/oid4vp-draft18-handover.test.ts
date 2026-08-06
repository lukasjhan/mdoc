import { describe, expect, it } from 'vitest'
import {
  cborEncode,
  DataItem,
  hex,
  NfcHandover,
  Oid4vpDraft18Handover,
  SessionTranscript,
  type SessionTranscriptStructure,
} from '../../src'
import { mdocContext } from '../context'

/**
 * ISO/IEC TS 18013-7:2025 Annex B, which normatively references OpenID4VP
 * Draft 18 (April 2023). B.4.4 replaces DeviceEngagementBytes and
 * EReaderKeyBytes with null and defines:
 *
 *   OID4VPHandover = [clientIdHash, responseUriHash, nonce]
 *
 * where clientIdHash is SHA-256 over `[clientId, mdocGeneratedNonce]` and
 * responseUriHash is SHA-256 over `[responseUri, mdocGeneratedNonce]`.
 */
describe('OpenID4VP draft 18 handover', () => {
  const clientId = 'Cq1anPb8vZU5j5C0d7hcsbuJLBpIawUJIDQRi2Ebwb4'
  const responseUri = 'http://localhost:4000/api/presentation_request/dc8999df/callback'
  const nonce = 'abcdefg'
  const mdocGeneratedNonce = '123456'

  /** The construction spelled out, straight from B.4.4. */
  const annexB = async (generatedNonce: string) => {
    const digest = async (value: string) =>
      await mdocContext.crypto.digest({
        digestAlgorithm: 'SHA-256',
        bytes: cborEncode([value, generatedNonce]),
      })

    return cborEncode(DataItem.fromData([null, null, [await digest(clientId), await digest(responseUri), nonce]]))
  }

  it('encodes what Annex B specifies, byte for byte', async () => {
    const transcript = await SessionTranscript.forOid4VpDraft18(
      { clientId, responseUri, verifierGeneratedNonce: nonce, mdocGeneratedNonce },
      mdocContext
    )

    expect(hex.encode(transcript.encode({ asDataItem: true }))).toBe(hex.encode(await annexB(mdocGeneratedNonce)))
  })

  it('accepts an empty mdocGeneratedNonce, as deployed verifiers send', async () => {
    const transcript = await SessionTranscript.forOid4VpDraft18(
      { clientId, responseUri, verifierGeneratedNonce: nonce, mdocGeneratedNonce: '' },
      mdocContext
    )

    expect(hex.encode(transcript.encode({ asDataItem: true }))).toBe(hex.encode(await annexB('')))
  })

  it('round-trips through a decode', async () => {
    const transcript = await SessionTranscript.forOid4VpDraft18(
      { clientId, responseUri, verifierGeneratedNonce: nonce, mdocGeneratedNonce },
      mdocContext
    )
    const bytes = transcript.encode()

    const decoded = SessionTranscript.decode(bytes)

    expect(decoded.handover).toBeInstanceOf(Oid4vpDraft18Handover)
    expect((decoded.handover as Oid4vpDraft18Handover).nonce).toBe(nonce)
    expect(hex.encode(decoded.encode())).toBe(hex.encode(bytes))
  })

  /**
   * NFCHandover is `[bstr, bstr / null]` and this one is `[bstr, bstr, tstr]`.
   * Both start with two byte strings, so without a length check whichever
   * candidate is tried first claims the structure -- and NFCHandover is tried
   * first.
   */
  it('is not mistaken for an NFC handover', async () => {
    const draft18 = (
      await SessionTranscript.forOid4VpDraft18(
        { clientId, responseUri, verifierGeneratedNonce: nonce, mdocGeneratedNonce },
        mdocContext
      )
    ).encodedStructure() as SessionTranscriptStructure

    expect(NfcHandover.isCorrectHandover(draft18[2])).toBe(false)
    expect(Oid4vpDraft18Handover.isCorrectHandover(draft18[2])).toBe(true)
  })

  it('does not claim an NFC handover either', () => {
    const nfc = new NfcHandover({ selectMessage: new Uint8Array([1, 2, 3]) }).encodedStructure()

    expect(Oid4vpDraft18Handover.isCorrectHandover(nfc)).toBe(false)
    expect(NfcHandover.isCorrectHandover(nfc)).toBe(true)
  })
})
