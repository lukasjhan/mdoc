import { describe, expect, test } from 'vitest'
import { DeviceKey } from '../../src/mdoc/models/device-key'
import { DeviceKeyInfo } from '../../src/mdoc/models/device-key-info'
import { MobileSecurityObject } from '../../src/mdoc/models/mobile-security-object'
import { Status, StatusListInfo } from '../../src/mdoc/models/status'
import { ValidityInfo } from '../../src/mdoc/models/validity-info'
import { ValueDigests } from '../../src/mdoc/models/value-digests'
import { DEVICE_JWK_PUBLIC } from '../config'

const STATUS_URI = 'https://issuer.example/status/mdl/1'

describe('status', () => {
  test('status_list round-trips through a CBOR encode/decode', () => {
    const status = new Status({ statusList: { idx: 42, uri: STATUS_URI } })

    const decoded = Status.decode(status.encode())

    expect(decoded.statusList).toBeInstanceOf(StatusListInfo)
    expect(decoded.statusList?.idx).toStrictEqual(42)
    expect(decoded.statusList?.uri).toStrictEqual(STATUS_URI)
  })

  test('unknown status members survive a round-trip', () => {
    const status = Status.fromEncodedStructure({
      status_list: { idx: 7, uri: STATUS_URI },
      identifier_list: { id: 'abc', uri: 'https://issuer.example/idlist/1' },
    })

    const decoded = Status.decode(status.encode())

    expect(decoded.statusList?.idx).toStrictEqual(7)
    expect(decoded.additional.get('identifier_list')).toBeDefined()
  })

  test('MSO carries status through encode/decode and omits it when absent', () => {
    const base = {
      digestAlgorithm: 'SHA-256' as const,
      docType: 'org.iso.18013.5.1.mDL',
      valueDigests: new ValueDigests({ valueDigests: new Map() }),
      deviceKeyInfo: new DeviceKeyInfo({ deviceKey: DeviceKey.fromJwk(DEVICE_JWK_PUBLIC) }),
      validityInfo: new ValidityInfo({
        signed: new Date('2024-01-01T00:00:00Z'),
        validFrom: new Date('2024-01-01T00:00:00Z'),
        validUntil: new Date('2035-01-01T00:00:00Z'),
      }),
    }

    const withStatus = MobileSecurityObject.decode(
      new MobileSecurityObject({ ...base, status: { statusList: { idx: 3, uri: STATUS_URI } } }).encode()
    )
    expect(withStatus.status?.statusList?.idx).toStrictEqual(3)
    expect(withStatus.status?.statusList?.uri).toStrictEqual(STATUS_URI)

    const withoutStatus = MobileSecurityObject.decode(new MobileSecurityObject(base).encode())
    expect(withoutStatus.status).toBeUndefined()
  })
})
