import { z } from 'zod'
import { CborStructure } from './cbor-structure'

/**
 * CBOR map keys are either text strings (ISO 18013-5 structures) or unsigned
 * integers (COSE structures). They are never coerced to one another -- a
 * `1` key and a `'1'` key are distinct entries on the wire.
 */
export type CborKey = string | number

/**
 * The in-memory form of a decoded CBOR map: keys in the order they appeared on
 * the wire, values already transformed into their modelled types.
 */
export type CborMap = Map<CborKey, unknown>

/** A single member of a CBOR map structure. */
export type CborField = readonly [key: CborKey, schema: z.ZodType]

type CborStructureClass<T extends CborStructure> = {
  new (...args: never[]): T
  fromEncodedStructure(encodedStructure: unknown): T
}

/**
 * A codec for a nested `CborStructure`.
 *
 * Decoding turns the nested map into an instance of `Class`; encoding asks the
 * instance for its own encoded structure. This is what lets a parent schema
 * declare `['validityInfo', cborStructure(ValidityInfo)]` and get both
 * directions for free.
 *
 * Encoding accepts any `CborStructure` rather than an instance of `Class`
 * exactly. Callers legitimately pass a base type where a narrower alias is
 * declared -- a `CoseKey` for a `DeviceKey`, say -- and the value's own
 * `encodedStructure` is what produces the bytes either way.
 */
export const cborStructure = <T extends CborStructure>(Class: CborStructureClass<T>) =>
  z.codec(
    z.unknown(),
    z.custom<T>((value) => value instanceof CborStructure),
    {
      decode: (encoded) => Class.fromEncodedStructure(encoded),
      encode: (instance) => instance.encodedStructure(),
    }
  )

/**
 * `cborMap` builds a bidirectional codec between the raw output of `cborDecode`
 * and a validated `CborMap`.
 *
 * Three properties matter for mdoc and are deliberate:
 *
 * 1. **Unknown keys survive.** ISO 18013-5 structures carry `* tstr => RFU`
 *    members, and a verifier must be able to re-encode a document it did not
 *    fully model. Keys absent from `fields` pass through untouched.
 * 2. **Wire order is preserved.** Re-encoding a decoded structure yields the
 *    original key order, so bytes covered by a signature stay byte-identical.
 *    Structures built in memory follow the order `fields` declares.
 * 3. **Absent optionals stay absent.** A key is only written when it has a
 *    value, so an unset optional never appears as an explicit `null`.
 */
export const cborMap = (fields: readonly CborField[]) => {
  const fieldSchemas = new Map<CborKey, z.ZodType>(fields.map(([key, schema]) => [key, schema]))
  const isOptional = (schema: z.ZodType) => schema.safeParse(undefined).success

  return z.codec(
    z.custom<Map<unknown, unknown>>((value) => value instanceof Map),
    z.custom<CborMap>((value) => value instanceof Map),
    {
      decode: (encoded, ctx) => {
        const decoded: CborMap = new Map()

        // Wire order first, so re-encoding reproduces the received bytes.
        for (const [key, value] of encoded) {
          const schema = fieldSchemas.get(key as CborKey)

          if (!schema) {
            decoded.set(key as CborKey, value)
            continue
          }

          const result = schema.safeParse(value)

          if (!result.success) {
            for (const issue of result.error.issues) {
              ctx.issues.push({
                code: 'custom',
                message: issue.message,
                path: [String(key), ...issue.path],
                input: value,
              })
            }
            continue
          }

          decoded.set(key as CborKey, result.data)
        }

        for (const [key, schema] of fieldSchemas) {
          if (encoded.has(key) || isOptional(schema)) continue

          ctx.issues.push({
            code: 'custom',
            message: `Expected key '${String(key)}' to be present`,
            path: [String(key)],
            input: undefined,
          })
        }

        return decoded
      },

      encode: (decoded) => {
        const encoded = new Map<unknown, unknown>()

        for (const [key, value] of decoded) {
          if (value === undefined) continue

          const schema = fieldSchemas.get(key)
          encoded.set(key, schema ? z.encode(schema, value) : value)
        }

        return encoded
      },
    }
  )
}

/**
 * A codec for a CBOR map whose keys are data rather than field names -- a
 * namespace-to-digests map, for instance. Every entry is validated against the
 * same pair of schemas, and insertion order is preserved in both directions.
 */
export const cborDynamicMap = (keySchema: z.ZodType, valueSchema: z.ZodType) =>
  z.codec(
    z.custom<Map<unknown, unknown>>((value) => value instanceof Map),
    z.custom<CborMap>((value) => value instanceof Map),
    {
      decode: (encoded, ctx) => {
        const decoded: CborMap = new Map()

        for (const [key, value] of encoded) {
          const parsedKey = keySchema.safeParse(key)
          const parsedValue = valueSchema.safeParse(value)

          for (const issue of [...(parsedKey.error?.issues ?? []), ...(parsedValue.error?.issues ?? [])]) {
            ctx.issues.push({
              code: 'custom',
              message: issue.message,
              path: [String(key), ...issue.path],
              input: value,
            })
          }

          if (parsedKey.success && parsedValue.success) decoded.set(parsedKey.data as CborKey, parsedValue.data)
        }

        return decoded
      },

      encode: (decoded) => new Map<unknown, unknown>(decoded),
    }
  )

/**
 * Builds the initial structure for a newly constructed model, in the order the
 * schema declares. Entries with an `undefined` value are dropped so that an
 * unset optional never reaches the wire.
 */
export const buildStructure = (entries: readonly (readonly [CborKey, unknown])[]): CborMap => {
  const structure: CborMap = new Map()

  for (const [key, value] of entries) {
    if (value !== undefined) structure.set(key, value)
  }

  return structure
}
