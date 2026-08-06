import { describe, expect, it } from 'vitest'
import { DeviceResponse, hex, ValidityInfo } from '../../src'
import { deviceResponse as animoDeviceResponse } from '../examples/animo-mdoc-05/deviceResponse'
import { deviceResponse as eudiReferenceDeviceResponse } from '../examples/eudi-reference/deviceResponse'

const msoPayloadAndReEncoding = (deviceResponse: Uint8Array) => {
  const document = DeviceResponse.decode(deviceResponse).documents?.[0]
  if (!document) throw new Error('no document in device response')

  const { issuerAuth } = document.issuerSigned

  return {
    received: hex.encode(issuerAuth.payload as Uint8Array),
    reEncoded: hex.encode(issuerAuth.mobileSecurityObject.encode({ asDataItem: true })),
  }
}

/**
 * The MSO is what the issuer signature covers, so re-encoding a decoded one
 * should reproduce the bytes it arrived as. These vectors come from four
 * independent implementations, which is what makes the check meaningful.
 *
 * Signature verification reads `issuerAuth.payload` directly and never
 * re-encodes, so the two known-lossy cases below do not affect verification.
 */
describe('MobileSecurityObject re-encodes to the received bytes', () => {
  it('eudi-reference', () => {
    const { received, reEncoded } = msoPayloadAndReEncoding(eudiReferenceDeviceResponse)
    expect(reEncoded).toBe(received)
  })
})

/**
 * One round trip is lossy, because of how this library encodes rather than how
 * it decodes. It predates the schema-backed models and is pinned here so that
 * any change to it is deliberate.
 */
describe('known lossy re-encodings', () => {
  it('normalises non-preferred map headers to their compact form (animo)', () => {
    const { received, reEncoded } = msoPayloadAndReEncoding(animoDeviceResponse)

    // The issuer emitted 16-bit map headers; b9 0006 is a 6-entry map written long-hand.
    expect(received).toContain('b90006')
    expect(reEncoded).toContain('a6')
    expect(reEncoded).not.toContain('b90006')
  })
})

describe('structures built in memory', () => {
  const base = {
    signed: new Date('2026-01-01T00:00:00Z'),
    validFrom: new Date('2026-01-01T00:00:00Z'),
    validUntil: new Date('2027-01-01T00:00:00Z'),
  }

  it('omits an unset optional rather than writing it as null', () => {
    const validityInfo = new ValidityInfo(base)

    expect(hex.encode(validityInfo.encode())).toMatch(/^a3/)
    expect(validityInfo.expectedUpdate).toBeUndefined()
  })

  it('includes an optional once it is set', () => {
    const validityInfo = new ValidityInfo({ ...base, expectedUpdate: new Date('2026-06-01T00:00:00Z') })

    expect(hex.encode(validityInfo.encode())).toMatch(/^a4/)
    expect(validityInfo.expectedUpdate).toEqual(new Date('2026-06-01T00:00:00Z'))
  })
})

describe('schema validation', () => {
  it('rejects a value of the wrong type, naming the key', () => {
    const malformed = new Map<string, unknown>([
      ['signed', new Date()],
      ['validFrom', new Date()],
      ['validUntil', 'not-a-date'],
    ])

    expect(() => ValidityInfo.fromEncodedStructure(malformed)).toThrow(/validUntil/)
  })

  it('rejects a structure missing a required key, naming the key', () => {
    const malformed = new Map<string, unknown>([['signed', new Date()]])

    expect(() => ValidityInfo.fromEncodedStructure(malformed)).toThrow(/validFrom/)
  })

  it('preserves unknown (RFU) members and their position', () => {
    const withRfu = new Map<string, unknown>([
      ['signed', new Date('2026-01-01T00:00:00Z')],
      ['validFrom', new Date('2026-01-01T00:00:00Z')],
      ['validUntil', new Date('2027-01-01T00:00:00Z')],
      ['someFutureField', 'RFU'],
    ])

    const reEncoded = ValidityInfo.fromEncodedStructure(withRfu).encodedStructure() as Map<string, unknown>

    expect(reEncoded.get('someFutureField')).toBe('RFU')
    expect([...reEncoded.keys()]).toEqual(['signed', 'validFrom', 'validUntil', 'someFutureField'])
  })
})
