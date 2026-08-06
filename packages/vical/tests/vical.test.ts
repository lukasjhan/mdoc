import { createMdocContext } from '@m-doc/context'
import { hex } from '@m-doc/core'
import { describe, expect, it } from 'vitest'
import { CertificateInfo, MDL_DOCTYPE, SignedVical, Vical } from '../src'
import { signedVicalBytes as bytes } from './fixtures/vical'

const ctx = createMdocContext()

describe('SignedVical', () => {
  it('decodes the COSE_Sign1 wrapper', () => {
    const signed = SignedVical.decode(bytes)

    expect(signed).toBeInstanceOf(SignedVical)
    expect(signed.signature).toBeDefined()
    expect(signed.payload).toBeDefined()
    expect(signed.signatureAlgorithmName).toBeDefined()
  })

  it('exposes the signer certificate from the x5chain header', () => {
    const signed = SignedVical.decode(bytes)

    expect(signed.certificate).toBeInstanceOf(Uint8Array)
    expect(signed.certificateChain.length).toBeGreaterThan(0)
  })

  it('verifies the provider signature against the certificate it carries', async () => {
    const signed = SignedVical.decode(bytes)

    await expect(signed.verify({}, ctx)).resolves.toBe(true)
  })

  it('re-encodes to the bytes it arrived as', () => {
    expect(hex.encode(SignedVical.decode(bytes).encode())).toBe(hex.encode(bytes))
  })
})

describe('Vical', () => {
  const vical = () => SignedVical.decode(bytes).vical

  it('reads the list header', () => {
    const list = vical()

    expect(list).toBeInstanceOf(Vical)
    expect(list.version).toBe('1.0')
    expect(list.vicalProvider).toBeTruthy()
    expect(list.date).toBeInstanceOf(Date)
  })

  it('reads the certificate entries', () => {
    const list = vical()

    expect(list.certificateInfos.length).toBeGreaterThan(0)

    for (const info of list.certificateInfos) {
      expect(info).toBeInstanceOf(CertificateInfo)
      expect(info.certificate).toBeInstanceOf(Uint8Array)
      expect(info.ski).toBeInstanceOf(Uint8Array)
      expect(typeof info.serialNumber).toBe('bigint')
      expect(info.docType.length).toBeGreaterThan(0)
    }
  })

  it('filters by docType', () => {
    const list = vical()
    const mdl = list.forDocType(MDL_DOCTYPE)

    expect(mdl.length).toBeGreaterThan(0)
    expect(mdl.every((info) => info.docType.includes(MDL_DOCTYPE))).toBe(true)
    expect(list.forDocType('does.not.exist')).toHaveLength(0)
  })

  it('finds an entry by country and by SKI', () => {
    const list = vical()
    const [first] = list.forDocType()

    if (first?.issuingCountry) {
      expect(list.forCountry(first.issuingCountry)).toBeDefined()
    }

    expect(list.forSubjectKeyIdentifier(first.ski)).toBeDefined()
    expect(list.forSubjectKeyIdentifier(new Uint8Array([0, 1, 2]))).toBeUndefined()
  })

  it('builds trust anchors keyed by country', () => {
    const anchors = vical().trustAnchors()

    expect(anchors.size).toBeGreaterThan(0)

    for (const [country, info] of anchors) {
      expect(info.issuingCountry).toBe(country)
      expect(info.docType).toContain(MDL_DOCTYPE)
    }
  })

  it('hands out the raw certificates', () => {
    const list = vical()

    expect(list.certificates()).toHaveLength(list.forDocType().length)
    expect(list.certificates()[0]).toBeInstanceOf(Uint8Array)
  })

  it('renders an entry as PEM', () => {
    const pem = vical().certificateInfos[0].toPem()

    expect(pem.startsWith('-----BEGIN CERTIFICATE-----\n')).toBe(true)
    expect(pem.endsWith('\n-----END CERTIFICATE-----')).toBe(true)
  })
})

describe('schema validation', () => {
  it('rejects a list missing a required member', () => {
    expect(() => Vical.fromEncodedStructure(new Map([['version', '1.0']]))).toThrow(/vicalProvider/)
  })

  it('rejects an entry whose certificate is not a byte string', () => {
    const malformed = new Map<string, unknown>([
      ['certificate', 'not-bytes'],
      ['serialNumber', 1],
      ['ski', new Uint8Array([1])],
      ['docType', [MDL_DOCTYPE]],
    ])

    expect(() => CertificateInfo.fromEncodedStructure(malformed)).toThrow(/certificate/)
  })
})
