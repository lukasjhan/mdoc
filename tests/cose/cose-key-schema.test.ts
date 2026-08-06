import { describe, expect, it } from 'vitest'
import { CoseKey, hex } from '../../src'
import { Curve } from '../../src/cose/key/curve'
import { CoseKeyParameter } from '../../src/cose/key/key'
import { KeyType } from '../../src/cose/key/key-type'
import { base64url } from '../../src/utils'

const x = base64url.decode('TgXwg173AdoB8XPXrF6d9QomYdvSFiMDM0vGH3pbvSw')
const y = base64url.decode('RvP1wJCz8Bcywp9KGXE3UxtnMK4h-BU0j12XLPsxM4Y')

describe('label -1 carries the curve or the key material, by key type', () => {
  it('reads it as a curve for EC2', () => {
    const key = CoseKey.fromEncodedStructure(
      new Map<number, unknown>([
        [CoseKeyParameter.KeyType, KeyType.Ec],
        [CoseKeyParameter.CurveOrK, Curve['P-256']],
      ])
    )

    expect(key.curve).toStrictEqual(Curve['P-256'])
    expect(key.k).toBeUndefined()
  })

  it('reads it as key material for Symmetric', () => {
    const secret = new Uint8Array([1, 2, 3, 4])
    const key = CoseKey.fromEncodedStructure(
      new Map<number, unknown>([
        [CoseKeyParameter.KeyType, KeyType.Oct],
        [CoseKeyParameter.CurveOrK, secret],
      ])
    )

    expect(key.k).toStrictEqual(secret)
    expect(key.curve).toBeUndefined()
    expect(key.privateKey).toStrictEqual(secret)
  })

  it('round-trips a symmetric key through the same slot', () => {
    const secret = new Uint8Array([9, 8, 7])
    const encoded = new CoseKey({ keyType: KeyType.Oct, k: secret }).encode()

    expect(CoseKey.decode(encoded).k).toStrictEqual(secret)
  })
})

describe('kid tolerates the non-conformant text-string form', () => {
  it('accepts a text-string kid, as the Animo vector emits', () => {
    const key = CoseKey.fromEncodedStructure(
      new Map<number, unknown>([
        [CoseKeyParameter.KeyType, KeyType.Ec],
        [CoseKeyParameter.KeyId, '24730abf-d90a-4a70-a1b1-ae7905d0b9e4'],
      ])
    )

    expect(key.keyId).toBe('24730abf-d90a-4a70-a1b1-ae7905d0b9e4')
  })

  it('writes bytes when given bytes', () => {
    const keyId = new Uint8Array([1, 2, 3])
    const encoded = new CoseKey({ keyType: KeyType.Ec, keyId }).encode()

    // 02 43 010203 -- label 2 holding a 3-byte string
    expect(hex.encode(encoded)).toContain('0243010203')
  })
})

describe('schema validation', () => {
  it('rejects a structure with no key type', () => {
    expect(() => CoseKey.fromEncodedStructure(new Map([[CoseKeyParameter.X, x]]))).toThrow()
  })

  it('rejects a coordinate that is not a byte string', () => {
    expect(() =>
      CoseKey.fromEncodedStructure(
        new Map<number, unknown>([
          [CoseKeyParameter.KeyType, KeyType.Ec],
          [CoseKeyParameter.X, 'not-bytes'],
        ])
      )
    ).toThrow(/-2/)
  })

  it('preserves unknown parameters across a round-trip', () => {
    const decoded = CoseKey.fromEncodedStructure(
      new Map<number, unknown>([
        [CoseKeyParameter.KeyType, KeyType.Ec],
        [CoseKeyParameter.X, x],
        [CoseKeyParameter.Y, y],
        [99, 'future'],
      ])
    )

    expect((decoded.encodedStructure() as Map<unknown, unknown>).get(99)).toBe('future')
  })
})
