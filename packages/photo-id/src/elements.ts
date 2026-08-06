/** The docType a PhotoID is issued under. ISO/IEC TS 23220-4:2026 Annex C. */
export const PHOTO_ID_DOC_TYPE = 'org.iso.23220.photoid.1'

/** The namespace of the common elements ISO/IEC TS 23220-2 defines. Table C.1. */
export const PHOTO_ID_BASE_NAMESPACE = 'org.iso.23220.1'

/** The namespace of the elements defined for PhotoID itself. Table C.2. */
export const PHOTO_ID_NAMESPACE = 'org.iso.23220.photoid.1'

/** The namespace carrying ICAO 9303 data groups. Table C.3. */
export const PHOTO_ID_DATAGROUPS_NAMESPACE = 'org.iso.23220.datagroups.1'

/**
 * The namespace a jurisdiction adds its own elements under, e.g.
 * `org.iso.23220.photoid.US-IA.1`.
 */
export const jurisdictionNamespace = (isoCountryOrSubdivisionCode: string) =>
  `org.iso.23220.photoid.${isoCountryOrSubdivisionCode}.1`

/** Elements a PhotoID must carry, in the base namespace. Table C.1, presence M. */
export const PHOTO_ID_MANDATORY_ELEMENTS = [
  'family_name',
  'given_name',
  'birth_date',
  'portrait',
  'issue_date',
  'expiry_date',
  'issuing_authority',
  'issuing_country',
  'age_over_18',
] as const

/** Elements Table C.1 recommends. */
export const PHOTO_ID_RECOMMENDED_ELEMENTS = ['age_in_years', 'age_over_NN', 'age_birth_year'] as const

/** Elements Table C.1 leaves optional. */
export const PHOTO_ID_OPTIONAL_ELEMENTS = [
  'portrait_capture_date',
  'birthplace',
  'name_at_birth',
  'resident_address',
  'resident_city',
  'resident_postal_code',
  'resident_country',
  'resident_city_latin1',
  'sex',
  'nationality',
  'document_number',
  'issuing_subdivision',
  'family_name_latin1',
  'given_name_latin1',
] as const

/** Elements defined for PhotoID itself, in `org.iso.23220.photoid.1`. Table C.2. */
export const PHOTO_ID_SPECIFIC_ELEMENTS = [
  'person_id',
  'birth_country',
  'birth_state',
  'birth_city',
  'administrative_number',
  'resident_street',
  'resident_house_number',
  'travel_document_type',
  'travel_document_number',
  'resident_state',
  'travel_document_mrz',
  'family_name_viz',
  'given_name_viz',
] as const

export type PhotoIdMandatoryElementIdentifier = (typeof PHOTO_ID_MANDATORY_ELEMENTS)[number]
export type PhotoIdBaseElementIdentifier =
  | PhotoIdMandatoryElementIdentifier
  | (typeof PHOTO_ID_OPTIONAL_ELEMENTS)[number]
  | `age_over_${number}`
  | 'age_in_years'
  | 'age_birth_year'

export type PhotoIdSpecificElementIdentifier = (typeof PHOTO_ID_SPECIFIC_ELEMENTS)[number]

/** The encoding formats ISO/IEC TS 23220-2 gives for these elements. */
export type PhotoIdEncoding = 'tstr' | 'bstr' | 'uint' | 'bool' | 'full-date' | 'tdate'

/**
 * How each element is encoded. Table C.1 defers to ISO/IEC TS 23220-2 for the
 * base-namespace elements; Table C.2 gives tstr for every element it defines.
 *
 * An `age_over_NN` is not listed, since NN is open; `encodingFor` answers for
 * those.
 */
export const PHOTO_ID_ELEMENT_ENCODING = {
  family_name: 'tstr',
  given_name: 'tstr',
  birth_date: 'full-date',
  portrait: 'bstr',
  issue_date: 'full-date',
  expiry_date: 'full-date',
  issuing_authority: 'tstr',
  issuing_country: 'tstr',
  age_over_18: 'bool',
  age_in_years: 'uint',
  age_birth_year: 'uint',
  portrait_capture_date: 'tdate',
  birthplace: 'tstr',
  name_at_birth: 'tstr',
  resident_address: 'tstr',
  resident_city: 'tstr',
  resident_postal_code: 'tstr',
  resident_country: 'tstr',
  resident_city_latin1: 'tstr',
  sex: 'uint',
  nationality: 'tstr',
  document_number: 'tstr',
  issuing_subdivision: 'tstr',
  family_name_latin1: 'tstr',
  given_name_latin1: 'tstr',
  person_id: 'tstr',
  birth_country: 'tstr',
  birth_state: 'tstr',
  birth_city: 'tstr',
  administrative_number: 'tstr',
  resident_street: 'tstr',
  resident_house_number: 'tstr',
  travel_document_type: 'tstr',
  travel_document_number: 'tstr',
  resident_state: 'tstr',
  travel_document_mrz: 'tstr',
  family_name_viz: 'tstr',
  given_name_viz: 'tstr',
} as const satisfies Record<string, PhotoIdEncoding>

/** How an element is encoded, or `undefined` for one this profile does not name. */
export const encodingFor = (identifier: string): PhotoIdEncoding | undefined => {
  if (/^age_over_\d{1,2}$/.test(identifier)) return 'bool'

  return (PHOTO_ID_ELEMENT_ENCODING as Record<string, PhotoIdEncoding>)[identifier]
}

/**
 * `sex`, as ISO/IEC 5218 defines it. Table C.1 notes that 9 is used for X,
 * where the base specification would leave it "not applicable".
 */
export const Sex = {
  NotKnown: 0,
  Male: 1,
  Female: 2,
  /** X, per the Table C.1 note. */
  X: 9,
} as const

export type SexValue = (typeof Sex)[keyof typeof Sex]
