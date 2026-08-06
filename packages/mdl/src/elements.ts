/** The docType an mDL is issued under. ISO/IEC 18013-5:2021 7.1. */
export const MDL_DOC_TYPE = 'org.iso.18013.5.1.mDL'

/** The namespace the elements of Table 5 live in. */
export const MDL_NAMESPACE = 'org.iso.18013.5.1'

/**
 * The namespace a jurisdiction adds its own elements under, e.g.
 * `org.iso.18013.5.1.DE`. ISO/IEC 18013-5:2021 7.2.8.
 */
export const jurisdictionNamespace = (isoCountryOrSubdivisionCode: string) =>
  `${MDL_NAMESPACE}.${isoCountryOrSubdivisionCode}`

/** Elements an mDL must carry. ISO/IEC 18013-5:2021 Table 5, presence M. */
export const MDL_MANDATORY_ELEMENTS = [
  'family_name',
  'given_name',
  'birth_date',
  'issue_date',
  'expiry_date',
  'issuing_country',
  'issuing_authority',
  'document_number',
  'portrait',
  'driving_privileges',
  'un_distinguishing_sign',
] as const

/** Elements an mDL may carry. ISO/IEC 18013-5:2021 Table 5, presence O. */
export const MDL_OPTIONAL_ELEMENTS = [
  'administrative_number',
  'sex',
  'height',
  'weight',
  'eye_colour',
  'hair_colour',
  'birth_place',
  'resident_address',
  'portrait_capture_date',
  'age_in_years',
  'age_birth_year',
  'issuing_jurisdiction',
  'nationality',
  'resident_city',
  'resident_state',
  'resident_postal_code',
  'resident_country',
  'family_name_national_character',
  'given_name_national_character',
  'signature_usual_mark',
] as const

export type MdlMandatoryElementIdentifier = (typeof MDL_MANDATORY_ELEMENTS)[number]
export type MdlOptionalElementIdentifier = (typeof MDL_OPTIONAL_ELEMENTS)[number]

/**
 * An age attestation identifier. `NN` runs from 00 to 99 and the value says
 * whether the holder is at least that old. ISO/IEC 18013-5:2021 7.2.5.
 */
export type AgeOverIdentifier = `age_over_${number}`

export type MdlElementIdentifier = MdlMandatoryElementIdentifier | MdlOptionalElementIdentifier | AgeOverIdentifier

/** The values Table 5 allows for `eye_colour`. */
export const EYE_COLOURS = [
  'black',
  'blue',
  'brown',
  'dichromatic',
  'grey',
  'green',
  'hazel',
  'maroon',
  'pink',
  'unknown',
] as const

/** The values Table 5 allows for `hair_colour`. */
export const HAIR_COLOURS = [
  'bald',
  'black',
  'blond',
  'brown',
  'grey',
  'red',
  'auburn',
  'sandy',
  'white',
  'unknown',
] as const

export type EyeColour = (typeof EYE_COLOURS)[number]
export type HairColour = (typeof HAIR_COLOURS)[number]

/** `sex`, as ISO/IEC 5218 defines it. */
export const Sex = {
  NotKnown: 0,
  Male: 1,
  Female: 2,
  NotApplicable: 9,
} as const

export type SexValue = (typeof Sex)[keyof typeof Sex]

/** The encoding formats Table 5 gives in its last column. */
export type MdlEncoding = 'tstr' | 'bstr' | 'uint' | 'bool' | 'full-date' | 'tdate' | 'tdate-or-full-date' | 'structure'

/**
 * How each element is encoded. ISO/IEC 18013-5:2021 Table 5.
 *
 * An `age_over_NN` is not listed, since NN is open; `encodingFor` answers for
 * those.
 */
export const MDL_ELEMENT_ENCODING = {
  family_name: 'tstr',
  given_name: 'tstr',
  birth_date: 'full-date',
  issue_date: 'tdate-or-full-date',
  expiry_date: 'tdate-or-full-date',
  issuing_country: 'tstr',
  issuing_authority: 'tstr',
  document_number: 'tstr',
  portrait: 'bstr',
  driving_privileges: 'structure',
  un_distinguishing_sign: 'tstr',
  administrative_number: 'tstr',
  sex: 'uint',
  height: 'uint',
  weight: 'uint',
  eye_colour: 'tstr',
  hair_colour: 'tstr',
  birth_place: 'tstr',
  resident_address: 'tstr',
  portrait_capture_date: 'tdate',
  age_in_years: 'uint',
  age_birth_year: 'uint',
  issuing_jurisdiction: 'tstr',
  nationality: 'tstr',
  resident_city: 'tstr',
  resident_state: 'tstr',
  resident_postal_code: 'tstr',
  resident_country: 'tstr',
  family_name_national_character: 'tstr',
  given_name_national_character: 'tstr',
  signature_usual_mark: 'bstr',
} as const satisfies Record<string, MdlEncoding>

const AGE_OVER = /^age_over_(\d{1,2})$/

/** How an element is encoded, or `undefined` for one this profile does not name. */
export const encodingFor = (identifier: string): MdlEncoding | undefined => {
  if (AGE_OVER.test(identifier)) return 'bool'

  return (MDL_ELEMENT_ENCODING as Record<string, MdlEncoding>)[identifier]
}

/** Whether an identifier is an `age_over_NN`, and what NN it names. */
export const parseAgeOverIdentifier = (identifier: string): number | undefined => {
  const match = AGE_OVER.exec(identifier)

  return match ? Number(match[1]) : undefined
}
