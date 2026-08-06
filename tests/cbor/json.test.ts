import { describe, expect, it } from 'vitest'
import { cborToJson, DateOnly } from '../../src'

describe('cborToJson', () => {
  it('passes primitives through', () => {
    expect(cborToJson('a')).toBe('a')
    expect(cborToJson(1)).toBe(1)
    expect(cborToJson(true)).toBe(true)
    expect(cborToJson(null)).toBeNull()
    expect(cborToJson(undefined)).toBeNull()
  })

  it('renders a bignum as a decimal string', () => {
    // JSON.stringify throws on a bigint
    expect(cborToJson(9007199254740993n)).toBe('9007199254740993')
  })

  it('renders a non-finite float as null, as JSON.stringify does', () => {
    expect(cborToJson(Number.POSITIVE_INFINITY)).toBeNull()
    expect(cborToJson(Number.NaN)).toBeNull()
  })

  it('renders a byte string as base64url by default', () => {
    expect(cborToJson(new Uint8Array([1, 2, 3]))).toBe('AQID')
  })

  it('renders a byte string as a data URI on request', () => {
    expect(cborToJson(new Uint8Array([1, 2, 3]), { bytes: 'dataUri' })).toBe(
      'data:application/octet-stream;base64,AQID'
    )
  })

  it('drops the fraction of a second from a tdate, matching the encoder', () => {
    expect(cborToJson(new Date('2026-02-19T12:00:00.210391Z'))).toBe('2026-02-19T12:00:00Z')
  })

  it('renders a full-date as a bare date', () => {
    expect(cborToJson(new DateOnly('2026-02-19'))).toBe('2026-02-19')
  })

  it('converts a map to an object, integer keys as decimal strings', () => {
    expect(
      cborToJson(
        new Map<unknown, unknown>([
          ['a', 1],
          [2, 'b'],
        ])
      )
    ).toEqual({ a: 1, '2': 'b' })
  })

  it('recurses through arrays and nested maps', () => {
    const value = new Map<string, unknown>([
      ['driving_privileges', [new Map([['vehicle_category_code', 'AM']])]],
      ['portrait', new Uint8Array([255])],
    ])

    expect(cborToJson(value)).toEqual({
      driving_privileges: [{ vehicle_category_code: 'AM' }],
      portrait: '_w',
    })
  })

  it('is JSON.stringify-safe', () => {
    const value = new Map<unknown, unknown>([
      ['bytes', new Uint8Array([1])],
      [1, 2n],
      ['when', new Date(0)],
    ])

    expect(JSON.stringify(cborToJson(value))).toBe('{"1":"2","bytes":"AQ","when":"1970-01-01T00:00:00Z"}')
  })
})

describe('documented losses', () => {
  it('reorders integer-like keys, as JavaScript objects do', () => {
    const value = new Map<unknown, unknown>([
      ['zeta', 1],
      [1, 2],
      ['alpha', 3],
      [0, 4],
    ])

    expect(Object.keys(cborToJson(value) as object)).toEqual(['0', '1', 'zeta', 'alpha'])
  })

  it('collides a key that is both 1 and "1"', () => {
    const value = new Map<unknown, unknown>([
      [1, 'integer'],
      ['1', 'text'],
    ])

    expect(cborToJson(value)).toEqual({ '1': 'text' })
  })
})
