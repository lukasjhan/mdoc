import { describe, expect, it } from 'vitest'
import { DeviceResponse, hex } from '../../src'
import { cborDecode } from '../../src/cbor'
import { deviceResponse as animo } from '../examples/animo-mdoc-05/deviceResponse'
import { deviceResponse as eudiReference } from '../examples/eudi-reference/deviceResponse'

const vectors = { animo, eudiReference }

/**
 * The protected headers are covered by the issuer signature: `toBeSigned`
 * embeds `protectedHeaders.encodedStructure()`. A decoded structure that
 * re-encodes to different bytes would fail verification, so the bytes have to
 * survive the round trip exactly.
 */
describe('protected headers re-encode to the bytes they arrived as', () => {
  for (const [name, deviceResponse] of Object.entries(vectors)) {
    it(name, () => {
      const raw = cborDecode<Map<string, unknown>>(deviceResponse, { mapsAsObjects: false })
      const documents = raw.get('documents') as unknown[]
      const issuerSigned = (documents[0] as Map<string, unknown>).get('issuerSigned') as Map<string, unknown>
      const received = (issuerSigned.get('issuerAuth') as unknown[])[0] as Uint8Array

      const document = DeviceResponse.decode(deviceResponse).documents?.[0]
      const reEncoded = document?.issuerSigned.issuerAuth.protectedHeaders.encodedStructure() as Uint8Array

      expect(hex.encode(reEncoded)).toBe(hex.encode(received))
    })
  }
})
