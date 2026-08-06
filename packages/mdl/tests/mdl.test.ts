import { DateOnly } from '@m-doc/core'
import { describe, expect, it } from 'vitest'
import {
  findMissingMandatoryElements,
  isExpired,
  isNotYetValid,
  jurisdictionNamespace,
  MDL_DOC_TYPE,
  MDL_NAMESPACE,
  privilegesFor,
  readDrivingPrivileges,
} from '../src'

describe('identifiers', () => {
  it('names the docType and namespace', () => {
    expect(MDL_DOC_TYPE).toBe('org.iso.18013.5.1.mDL')
    expect(MDL_NAMESPACE).toBe('org.iso.18013.5.1')
    expect(jurisdictionNamespace('DE')).toBe('org.iso.18013.5.1.DE')
  })
})

describe('readDrivingPrivileges', () => {
  it('reads the decoded CBOR shape', () => {
    const claim = [
      new Map<string, unknown>([
        ['vehicle_category_code', 'B'],
        ['issue_date', new DateOnly('2020-01-01')],
        ['expiry_date', new DateOnly('2030-01-01')],
        [
          'codes',
          [
            new Map([
              ['code', '01'],
              ['sign', '='],
              ['value', '1'],
            ]),
          ],
        ],
      ]),
      new Map<string, unknown>([['vehicle_category_code', 'AM']]),
    ]

    const privileges = readDrivingPrivileges(claim)

    expect(privileges).toHaveLength(2)
    expect(privileges[0]).toMatchObject({ vehicleCategoryCode: 'B' })
    expect(privileges[0].issueDate?.toISOString()).toBe('2020-01-01')
    expect(privileges[0].codes).toEqual([{ code: '01', sign: '=', value: '1' }])
    expect(privileges[1]).toEqual({ vehicleCategoryCode: 'AM' })
  })

  it('skips an entry with no vehicle category code', () => {
    // The field is mandatory; an entry without it names no category
    expect(readDrivingPrivileges([new Map([['issue_date', '2020-01-01']])])).toEqual([])
  })

  it('tolerates a claim that was never disclosed', () => {
    expect(readDrivingPrivileges(undefined)).toEqual([])
    expect(readDrivingPrivileges([])).toEqual([])
  })

  it('finds the privileges for a category', () => {
    const claim = [new Map([['vehicle_category_code', 'B']]), new Map([['vehicle_category_code', 'A']])]

    expect(privilegesFor(claim, 'A')).toHaveLength(1)
    expect(privilegesFor(claim, 'C')).toHaveLength(0)
  })
})

describe('profile', () => {
  const complete = {
    family_name: 'Han',
    given_name: 'Lukas',
    birth_date: new DateOnly('2000-01-01'),
    issue_date: new DateOnly('2020-01-01'),
    expiry_date: new DateOnly('2030-01-01'),
    issuing_country: 'NL',
    issuing_authority: 'RDW',
    document_number: '1234',
    portrait: new Uint8Array([1]),
    driving_privileges: [],
    un_distinguishing_sign: 'NL',
  }

  it('reports nothing missing on a complete document', () => {
    expect(findMissingMandatoryElements(complete)).toEqual([])
  })

  it('names what a selectively disclosed document left out', () => {
    const missing = findMissingMandatoryElements({ family_name: 'Han', given_name: 'Lukas' })

    expect(missing).toContain('portrait')
    expect(missing).toContain('driving_privileges')
    expect(missing).not.toContain('family_name')
  })

  it('reads the validity dates', () => {
    expect(isExpired(complete, new Date('2026-01-01'))).toBe(false)
    expect(isExpired(complete, new Date('2031-01-01'))).toBe(true)
    expect(isNotYetValid(complete, new Date('2019-01-01'))).toBe(true)
    expect(isNotYetValid(complete, new Date('2026-01-01'))).toBe(false)
  })

  it('says undefined rather than false when the date was not disclosed', () => {
    expect(isExpired({})).toBeUndefined()
    expect(isNotYetValid({})).toBeUndefined()
  })
})
