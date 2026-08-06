import { describe, expect, it } from 'vitest'
import { cborEncode, hex, IsoMdocDcApiHandover, SessionTranscript } from '../../src'
import { mdocContext } from '../context'

const encryptionInfoBase64Url = 'gqZ0ZW5jcnlwdGlvbkluZm8'
const origin = 'https://verifier.example.com'

describe('IsoMdocDcApiHandover', () => {
  it('produces [null, null, ["dcapi", SHA-256(CBOR([encInfo, origin]))]]', async () => {
    const transcript = await SessionTranscript.forIsoMdocDcApi({ encryptionInfoBase64Url, origin }, mdocContext)

    const expectedHash = await mdocContext.crypto.digest({
      digestAlgorithm: 'SHA-256',
      bytes: cborEncode([encryptionInfoBase64Url, origin]),
    })
    const expected = cborEncode([null, null, ['dcapi', expectedHash]])

    expect(hex.encode(transcript.encode())).toBe(hex.encode(expected))
  })

  it('is recognised when decoding a transcript back', async () => {
    const transcript = await SessionTranscript.forIsoMdocDcApi({ encryptionInfoBase64Url, origin }, mdocContext)
    const decoded = SessionTranscript.decode(transcript.encode())

    expect(decoded.handover).toBeInstanceOf(IsoMdocDcApiHandover)
    expect(decoded.deviceEngagement).toBeUndefined()
    expect(decoded.eReaderKey).toBeUndefined()
    expect(hex.encode(decoded.encode())).toBe(hex.encode(transcript.encode()))
  })

  it('can be built from a hash alone', async () => {
    const hash = new Uint8Array(32).fill(3)
    const handover = await new IsoMdocDcApiHandover({ dcApiInfoHash: hash }).prepare(mdocContext)

    expect(handover.dcApiInfoHash).toStrictEqual(hash)
    // 65 = text(5), then "dcapi"
    expect(hex.encode(new SessionTranscript({ handover }).encode())).toContain('656463617069')
  })

  it('refuses to encode before the hash exists', () => {
    expect(() => new IsoMdocDcApiHandover({ encryptionInfoBase64Url, origin }).encode()).toThrow(/prepare/)
  })

  it('preparing returns a copy rather than filling in the receiver', async () => {
    const handover = new IsoMdocDcApiHandover({ encryptionInfoBase64Url, origin })
    const prepared = await handover.prepare(mdocContext)

    expect(prepared).not.toBe(handover)
    expect(handover.dcApiInfoHash).toBeUndefined()
    expect(prepared.dcApiInfoHash).toBeDefined()
  })
})
