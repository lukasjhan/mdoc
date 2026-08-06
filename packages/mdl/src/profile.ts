import type { DateOnly } from '@m-doc/core'
import { MDL_MANDATORY_ELEMENTS, type MdlMandatoryElementIdentifier } from './elements'

/**
 * The mandatory elements a set of claims does not carry. ISO/IEC 18013-5:2021
 * Table 5.
 *
 * An mDL is allowed to disclose a subset — that is the point of selective
 * disclosure — so a non-empty result is only a finding on a document that was
 * meant to be complete, such as one straight from an issuer.
 */
export const findMissingMandatoryElements = (claims: Record<string, unknown>): Array<MdlMandatoryElementIdentifier> =>
  MDL_MANDATORY_ELEMENTS.filter((element) => claims[element] === undefined)

/**
 * Whether the document has passed its `expiry_date`.
 *
 * Returns `undefined` when the claim was not disclosed, which is not the same
 * as "not expired".
 */
export const isExpired = (claims: Record<string, unknown>, now: Date = new Date()): boolean | undefined => {
  const expiry = toDate(claims.expiry_date)

  return expiry ? expiry.getTime() < now.getTime() : undefined
}

/**
 * Whether the document's `issue_date` is in the future.
 *
 * Returns `undefined` when the claim was not disclosed.
 */
export const isNotYetValid = (claims: Record<string, unknown>, now: Date = new Date()): boolean | undefined => {
  const issued = toDate(claims.issue_date)

  return issued ? issued.getTime() > now.getTime() : undefined
}

const toDate = (value: unknown): Date | undefined => {
  if (value instanceof Date) return value
  if (typeof value === 'string') return new Date(value)

  // A full-date arrives as a DateOnly, whose toISOString gives YYYY-MM-DD
  const dateOnly = value as DateOnly | undefined

  return typeof dateOnly?.toISOString === 'function' ? new Date(dateOnly.toISOString()) : undefined
}
