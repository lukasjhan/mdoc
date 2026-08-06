import type { DateOnly } from '@m-doc/core'
import { type AgeOverIdentifier, parseAgeOverIdentifier } from './elements'

export type AgeAttestation = {
  identifier: AgeOverIdentifier
  /** The NN of `age_over_NN`. */
  age: number
  value: boolean
}

/** Every `age_over_NN` a set of claims carries, in ascending order of NN. */
export const readAgeAttestations = (claims: Record<string, unknown>): Array<AgeAttestation> => {
  const attestations: Array<AgeAttestation> = []

  for (const [identifier, value] of Object.entries(claims)) {
    const age = parseAgeOverIdentifier(identifier)

    if (age !== undefined && typeof value === 'boolean') {
      attestations.push({ identifier: identifier as AgeOverIdentifier, age, value })
    }
  }

  return attestations.sort((a, b) => a.age - b.age)
}

/**
 * Picks the attestation to answer an `age_over_NN` request with, per ISO/IEC
 * 18013-5:2021 7.2.5.
 *
 * A request for `age_over_NN` means "the nearest attestation at or above NN
 * that is TRUE, or below NN that is FALSE" — not the exact identifier:
 *
 * 1. Among the TRUE attestations, take those with `nn >= NN`, and of those the
 *    one closest to NN.
 * 2. Failing that, among the FALSE attestations, take those with `nn <= NN`,
 *    and of those the one closest to NN.
 * 3. Failing that, answer with nothing.
 *
 * Returning the identifier that was literally asked for, or nothing when it is
 * absent, is the common mistake: an mDL holding only `age_over_21: true`
 * should still answer a request for `age_over_18`.
 */
export const resolveAgeAttestation = (
  claims: Record<string, unknown>,
  requestedAge: number
): AgeAttestation | undefined => {
  const attestations = readAgeAttestations(claims)

  const nearest = (candidates: Array<AgeAttestation>) =>
    candidates.reduce<AgeAttestation | undefined>(
      (best, candidate) =>
        !best || Math.abs(candidate.age - requestedAge) < Math.abs(best.age - requestedAge) ? candidate : best,
      undefined
    )

  return (
    nearest(attestations.filter((a) => a.value && a.age >= requestedAge)) ??
    nearest(attestations.filter((a) => !a.value && a.age <= requestedAge))
  )
}

/**
 * The `age_over_NN` elements to issue, evaluated at `validFrom`.
 *
 * 7.2.5 requires the values to be valid at the MSO's `validFrom`, not at the
 * moment of issuance, so that is what the caller passes.
 */
export const buildAgeAttestations = (
  birthDate: DateOnly | Date | string,
  validFrom: Date,
  ages: ReadonlyArray<number>
): Record<AgeOverIdentifier, boolean> => {
  const age = ageAt(birthDate, validFrom)
  const attestations: Record<string, boolean> = {}

  for (const nn of ages) {
    attestations[`age_over_${nn}`] = age >= nn
  }

  return attestations
}

/** Whole years elapsed between a date of birth and a moment. */
export const ageAt = (birthDate: DateOnly | Date | string, at: Date): number => {
  const born = new Date(typeof birthDate === 'string' ? birthDate : birthDate.toISOString())

  let age = at.getUTCFullYear() - born.getUTCFullYear()
  const monthDelta = at.getUTCMonth() - born.getUTCMonth()

  if (monthDelta < 0 || (monthDelta === 0 && at.getUTCDate() < born.getUTCDate())) age--

  return age
}
