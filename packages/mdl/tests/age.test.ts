import { DateOnly } from '@m-doc/core'
import { describe, expect, it } from 'vitest'
import { ageAt, buildAgeAttestations, readAgeAttestations, resolveAgeAttestation } from '../src'

describe('resolveAgeAttestation', () => {
  /**
   * ISO/IEC 18013-5:2021 7.2.5 step 1: among the TRUE attestations at or above
   * the requested age, answer with the closest one.
   */
  it('answers a request with the nearest TRUE at or above it', () => {
    const claims = { age_over_18: true, age_over_21: true, age_over_65: false }

    expect(resolveAgeAttestation(claims, 18)).toMatchObject({ identifier: 'age_over_18', value: true })
    expect(resolveAgeAttestation(claims, 20)).toMatchObject({ identifier: 'age_over_21', value: true })
  })

  it('answers a request the document has no exact element for', () => {
    // The common mistake is returning nothing here
    expect(resolveAgeAttestation({ age_over_21: true }, 18)).toMatchObject({
      identifier: 'age_over_21',
      value: true,
    })
  })

  /** Step 2: falling back to the nearest FALSE at or below the request. */
  it('falls back to the nearest FALSE at or below', () => {
    const claims = { age_over_18: false, age_over_16: false }

    expect(resolveAgeAttestation(claims, 21)).toMatchObject({ identifier: 'age_over_18', value: false })
  })

  it('prefers a TRUE above over a FALSE below', () => {
    const claims = { age_over_16: false, age_over_21: true }

    expect(resolveAgeAttestation(claims, 18)).toMatchObject({ identifier: 'age_over_21', value: true })
  })

  /** Step 3: no answer at all. */
  it('answers with nothing when neither step produces one', () => {
    // Step 2 only takes FALSE attestations at or *below* the request: knowing
    // the holder is not over 65 says nothing about whether they are over 18
    expect(resolveAgeAttestation({ age_over_65: false }, 18)).toBeUndefined()
    expect(resolveAgeAttestation({ family_name: 'Han' }, 18)).toBeUndefined()
    expect(resolveAgeAttestation({}, 18)).toBeUndefined()
  })

  it('ignores age_over elements that are not booleans', () => {
    expect(resolveAgeAttestation({ age_over_18: 'yes' }, 18)).toBeUndefined()
  })
})

describe('readAgeAttestations', () => {
  it('collects them in ascending order', () => {
    const attestations = readAgeAttestations({ age_over_65: false, age_over_18: true, family_name: 'Han' })

    expect(attestations.map((a) => a.age)).toEqual([18, 65])
    expect(attestations[0]).toMatchObject({ identifier: 'age_over_18', age: 18, value: true })
  })
})

describe('buildAgeAttestations', () => {
  it('evaluates each age at the MSO validFrom, not at issuance', () => {
    // 7.2.5 requires the values to hold at validFrom
    const attestations = buildAgeAttestations(
      new DateOnly('2005-06-15'),
      new Date('2026-01-01T00:00:00Z'),
      [16, 18, 21, 65]
    )

    expect(attestations).toEqual({
      age_over_16: true,
      age_over_18: true,
      age_over_21: false,
      age_over_65: false,
    })
  })

  it('accepts a plain date string', () => {
    expect(buildAgeAttestations('2000-01-01', new Date('2026-01-01T00:00:00Z'), [18])).toEqual({
      age_over_18: true,
    })
  })
})

describe('ageAt', () => {
  it('counts whole years', () => {
    expect(ageAt('2000-06-15', new Date('2026-06-14T00:00:00Z'))).toBe(25)
    expect(ageAt('2000-06-15', new Date('2026-06-15T00:00:00Z'))).toBe(26)
  })
})
