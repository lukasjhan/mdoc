import { describe, expect, it } from 'vitest'
import { hex } from '../../src'
import { DeviceNamespaces } from '../../src/mdoc/models/device-namespaces'
import { DeviceSignedItems } from '../../src/mdoc/models/device-signed-items'
import { ErrorItems } from '../../src/mdoc/models/error-items'
import { Errors } from '../../src/mdoc/models/errors'

/**
 * A map keyed by data whose values are themselves structures has to run the
 * value schema in both directions. Every device-response vector carries an
 * empty `deviceSigned.nameSpaces`, so a populated one is checked here instead.
 */
describe('maps of nested structures encode their values', () => {
  it('DeviceNamespaces', () => {
    const namespaces = new DeviceNamespaces({
      deviceNamespaces: new Map([
        ['org.iso.18013.5.1', new DeviceSignedItems({ deviceSignedItems: new Map([['family_name', 'Smith']]) })],
      ]),
    })

    const encoded = namespaces.encodedStructure()
    const inner = encoded.get('org.iso.18013.5.1')

    expect(inner).toBeInstanceOf(Map)
    expect(inner).not.toBeInstanceOf(DeviceSignedItems)
    expect((inner as Map<string, unknown>).get('family_name')).toBe('Smith')

    // a1 71 "org.iso.18013.5.1" a1 6b "family_name" 65 "Smith"
    expect(hex.encode(namespaces.encode())).toMatch(/^a171/)

    const decoded = DeviceNamespaces.decode(namespaces.encode())
    expect(decoded.deviceNamespaces.get('org.iso.18013.5.1')).toBeInstanceOf(DeviceSignedItems)
    expect(decoded.deviceNamespaces.get('org.iso.18013.5.1')?.deviceSignedItems.get('family_name')).toBe('Smith')
  })

  it('Errors', () => {
    const errors = new Errors({
      errors: new Map([['org.iso.18013.5.1', new ErrorItems({ errorItems: new Map([['family_name', 0]]) })]]),
    })

    const encoded = errors.encodedStructure() as Map<string, Map<string, number>>
    const inner = encoded.get('org.iso.18013.5.1') as Map<string, number>

    expect(inner).toBeInstanceOf(Map)
    expect(inner.get('family_name')).toBe(0)

    const decoded = Errors.decode(errors.encode())
    expect(decoded.errors.get('org.iso.18013.5.1')?.errorItems.get('family_name')).toBe(0)
  })
})
