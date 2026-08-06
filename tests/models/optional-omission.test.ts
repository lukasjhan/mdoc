import { describe, expect, it } from 'vitest'
import { hex } from '../../src'
import { KeyAuthorizations } from '../../src/mdoc/models/key-authorizations'

/**
 * ISO 18013-5 declares these members as `? "nameSpaces"` and `? "dataElements"`.
 * The hand-written encoder used to emit both keys unconditionally with a CBOR
 * undefined (0xf7) value when they were unset, producing
 * `a2 6a "nameSpaces" f7 6c "dataElements" f7` for an empty structure. A key
 * that is absent has to be absent.
 */
describe('absent optional members are left out, not written as undefined', () => {
  it('encodes an empty KeyAuthorizations as an empty map', () => {
    expect(hex.encode(new KeyAuthorizations({}).encode())).toBe('a0')
  })

  it('writes only the member that is set', () => {
    const encoded = hex.encode(new KeyAuthorizations({ namespaces: ['a'] }).encode())

    // a1 6a "nameSpaces" 81 61 "a"
    expect(encoded).toBe('a16a6e616d65537061636573816161')
    expect(encoded).not.toContain('f7')
  })

  it('round-trips through decode', () => {
    const original = new KeyAuthorizations({ namespaces: ['org.iso.18013.5.1'] })
    const decoded = KeyAuthorizations.decode(original.encode())

    expect(decoded.namespaces).toEqual(['org.iso.18013.5.1'])
    expect(decoded.dataElements).toBeUndefined()
  })
})
