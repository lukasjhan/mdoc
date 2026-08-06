import { DateOnly } from '@m-doc/core'

/**
 * One code on a driving privilege — a restriction, condition or endorsement.
 * ISO/IEC 18013-2 Annex A.
 */
export type DrivingPrivilegeCode = {
  code: string
  sign?: string
  value?: string
}

/**
 * One category the holder is licenced for. ISO/IEC 18013-5:2021 7.2.4.
 *
 *   DrivingPrivilege = {
 *     "vehicle_category_code": tstr,
 *     ? "issue_date": full-date,
 *     ? "expiry_date": full-date,
 *     ? "codes": [+ Code]
 *   }
 */
export type DrivingPrivilege = {
  vehicleCategoryCode: string
  issueDate?: DateOnly
  expiryDate?: DateOnly
  codes?: Array<DrivingPrivilegeCode>
}

const read = (source: unknown, key: string): unknown =>
  source instanceof Map ? source.get(key) : (source as Record<string, unknown> | undefined)?.[key]

const asDateOnly = (value: unknown): DateOnly | undefined => {
  if (value instanceof DateOnly) return value
  if (typeof value === 'string') return new DateOnly(value)

  return undefined
}

const readCode = (source: unknown): DrivingPrivilegeCode | undefined => {
  const code = read(source, 'code')
  if (typeof code !== 'string') return undefined

  const sign = read(source, 'sign')
  const value = read(source, 'value')

  return {
    code,
    ...(typeof sign === 'string' ? { sign } : {}),
    ...(typeof value === 'string' ? { value } : {}),
  }
}

/**
 * Reads the `driving_privileges` claim into typed values.
 *
 * The claim arrives as decoded CBOR — an array of `Map`s — so this turns it
 * into something a caller can read without reaching into Maps. Entries with no
 * `vehicle_category_code` are skipped: the field is mandatory, and an entry
 * without it names no category.
 */
export const readDrivingPrivileges = (value: unknown): Array<DrivingPrivilege> => {
  if (!Array.isArray(value)) return []

  const privileges: Array<DrivingPrivilege> = []

  for (const entry of value) {
    const vehicleCategoryCode = read(entry, 'vehicle_category_code')
    if (typeof vehicleCategoryCode !== 'string') continue

    const issueDate = asDateOnly(read(entry, 'issue_date'))
    const expiryDate = asDateOnly(read(entry, 'expiry_date'))
    const rawCodes = read(entry, 'codes')
    const codes = Array.isArray(rawCodes)
      ? rawCodes.map(readCode).filter((c): c is DrivingPrivilegeCode => !!c)
      : undefined

    privileges.push({
      vehicleCategoryCode,
      ...(issueDate ? { issueDate } : {}),
      ...(expiryDate ? { expiryDate } : {}),
      ...(codes?.length ? { codes } : {}),
    })
  }

  return privileges
}

/** The privileges for a vehicle category, if the holder has any. */
export const privilegesFor = (value: unknown, vehicleCategoryCode: string): Array<DrivingPrivilege> =>
  readDrivingPrivileges(value).filter((privilege) => privilege.vehicleCategoryCode === vehicleCategoryCode)
