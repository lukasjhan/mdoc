import { PHOTO_ID_MANDATORY_ELEMENTS, type PhotoIdMandatoryElementIdentifier } from './elements'

/**
 * The mandatory elements a set of base-namespace claims does not carry. ISO/IEC
 * TS 23220-4:2026 Table C.1.
 *
 * A PhotoID is allowed to disclose a subset, so a non-empty result is only a
 * finding on a document that was meant to be complete.
 */
export const findMissingMandatoryElements = (
  claims: Record<string, unknown>
): Array<PhotoIdMandatoryElementIdentifier> =>
  PHOTO_ID_MANDATORY_ELEMENTS.filter((element) => claims[element] === undefined)

export type TravelDocumentIssue = {
  element: 'travel_document_type' | 'travel_document_mrz'
  reason: string
}

/**
 * Checks the conditional rule Table C.2 puts on the travel-document elements:
 * where `dg1` is present, `travel_document_type` and `travel_document_mrz`
 * shall be too. They are optional otherwise.
 *
 * `dg1` lives in the data-group namespace and the two elements in the PhotoID
 * namespace, so both sets of claims are needed to judge it.
 */
export const findTravelDocumentIssues = (options: {
  photoIdClaims: Record<string, unknown>
  dataGroupClaims?: Record<string, unknown>
}): Array<TravelDocumentIssue> => {
  if (options.dataGroupClaims?.dg1 === undefined) return []

  const issues: Array<TravelDocumentIssue> = []

  for (const element of ['travel_document_type', 'travel_document_mrz'] as const) {
    if (options.photoIdClaims[element] === undefined) {
      issues.push({ element, reason: `${element} is required when dg1 is present` })
    }
  }

  return issues
}
