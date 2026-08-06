import { describe, expect, it } from 'vitest'
import { Header, hex, ProtectedHeaders, Sign1, SignatureAlgorithm, UnprotectedHeaders } from '../../src'

const build = (options: { detachedContent?: Uint8Array; signature?: Uint8Array } = {}) =>
  new Sign1({
    protectedHeaders: new ProtectedHeaders({
      protectedHeaders: new Map([[Header.Algorithm, SignatureAlgorithm.ES256]]),
    }),
    unprotectedHeaders: new UnprotectedHeaders({ unprotectedHeaders: new Map() }),
    payload: new Uint8Array([1, 2, 3]),
    ...options,
  })

describe('Sign1 wire data is fixed once the structure exists', () => {
  it('withDetachedContent returns a copy and leaves the receiver alone', () => {
    const original = build()
    const derived = original.withDetachedContent(new Uint8Array([9, 9, 9]))

    expect(derived).not.toBe(original)
    expect(original.detachedContent).toBeUndefined()
    expect(derived.detachedContent).toStrictEqual(new Uint8Array([9, 9, 9]))

    // The wire structure is shared, not copied apart
    expect(derived.payload).toStrictEqual(original.payload)
    expect(derived.protectedHeaders).toBe(original.protectedHeaders)
  })

  it('preserves the subclass through a copy', () => {
    class Custom extends Sign1 {}

    const derived = new Custom({ payload: new Uint8Array([1]) }).withDetachedContent(new Uint8Array([2]))

    expect(derived).toBeInstanceOf(Custom)
  })

  it('toBeSigned reflects the detached content of the structure it is read from', () => {
    const original = build()
    const derived = original.withDetachedContent(new Uint8Array([9, 9, 9]))

    // Reading the receiver first would have poisoned a shared cache
    const originalTbs = hex.encode(original.toBeSigned)
    const derivedTbs = hex.encode(derived.toBeSigned)

    expect(originalTbs).not.toBe(derivedTbs)
    expect(originalTbs).toBe(hex.encode(original.toBeSigned))
    expect(derivedTbs).toBe(hex.encode(derived.toBeSigned))
  })

  it('refuses to encode without a signature', () => {
    expect(() => build().encode()).toThrow(/signature/i)
  })

  it('encodes once a signature is present', () => {
    const signature = new Uint8Array(64).fill(7)

    // 84 = 4-element array, the COSE_Sign1 shape
    expect(hex.encode(build({ signature }).encode())).toMatch(/^84/)
  })
})
