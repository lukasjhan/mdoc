import { z } from 'zod'
import { CborStructure } from './cbor-structure'
import { DataItem } from './data-item'

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

// Only the static decoder is needed, so a model may keep its constructor
// private -- IssuerSignedItem builds through fromOptions instead.
type CborStructureClass<T extends CborStructure> = {
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
 * A codec for a nested structure that the wire format wraps in a tag-24 data
 * item -- `#6.24(bstr .cbor Structure)`, which ISO 18013-5 uses wherever a
 * structure has to be hashed or signed as an opaque blob.
 */
export const cborDataItem = <T extends CborStructure>(Class: CborStructureClass<T>) =>
  z.codec(
    z.custom<DataItem>((value) => value instanceof DataItem),
    z.custom<T>((value) => value instanceof CborStructure),
    {
      decode: (dataItem) => Class.fromEncodedStructure(dataItem.data),
      encode: (instance) => DataItem.fromData(instance.encodedStructure()),
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
/**
 * `cborDecode` yields a `Map`, but callers hand structures in as plain objects
 * too -- which is what the hand-written decoders accepted before. Both are read.
 */
export const asEntries = (value: unknown): Map<unknown, unknown> | undefined => {
  if (value instanceof Map) return value

  if (value && typeof value === 'object' && !Array.isArray(value) && !ArrayBuffer.isView(value)) {
    return new Map<unknown, unknown>(Object.entries(value))
  }

  return undefined
}

export const cborMap = (fields: readonly CborField[]) => {
  const fieldSchemas = new Map<CborKey, z.ZodType>(fields.map(([key, schema]) => [key, schema]))
  const isOptional = (schema: z.ZodType) => schema.safeParse(undefined).success

  return z.codec(
    z.custom<Map<unknown, unknown> | Record<string, unknown>>((value) => asEntries(value) !== undefined),
    z.custom<CborMap>((value) => value instanceof Map),
    {
      decode: (input, ctx) => {
        const encoded = asEntries(input) as Map<unknown, unknown>
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
 * A codec for a CBOR array whose positions are fixed -- the four elements of a
 * COSE_Sign1, for instance.
 *
 * Positions are named so that a model can expose `signature` rather than
 * `structure[3]`, but the wire form stays an array: decoding maps each position
 * onto its name, encoding writes the names back out in declaration order.
 *
 * A field whose schema accepts `undefined` may be absent when encoding, and any
 * trailing absent field is simply not written. A required field that is missing
 * is an error, which is what makes an unsigned `Sign1` fail to encode.
 */
export const cborArray = (fields: readonly CborField[]) =>
  z.codec(
    z.custom<unknown[]>((value) => Array.isArray(value)),
    z.custom<CborMap>((value) => value instanceof Map),
    {
      decode: (encoded, ctx) => {
        const decoded: CborMap = new Map()

        fields.forEach(([key, schema], index) => {
          const result = schema.safeParse(encoded[index])

          if (!result.success) {
            for (const issue of result.error.issues) {
              ctx.issues.push({
                code: 'custom',
                message: issue.message,
                path: [String(key), ...issue.path],
                input: encoded[index],
              })
            }
            return
          }

          if (result.data !== undefined) decoded.set(key, result.data)
        })

        return decoded
      },

      encode: (decoded) => {
        const encoded: unknown[] = []

        for (const [key, schema] of fields) {
          const value = decoded.get(key)

          if (value === undefined) {
            if (!schema.safeParse(undefined).success) {
              throw new Error(`Cannot encode: '${String(key)}' is required but not set`)
            }

            encoded.push(undefined)
            continue
          }

          encoded.push(z.encode(schema, value))
        }

        while (encoded.length > 0 && encoded[encoded.length - 1] === undefined) encoded.pop()

        return encoded
      },
    }
  )

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

      encode: (decoded) => {
        const encoded = new Map<unknown, unknown>()

        // The value schema has to run here too: for a map of nested structures
        // it is what turns each instance back into its encoded form.
        for (const [key, value] of decoded) {
          encoded.set(key, z.encode(valueSchema, value))
        }

        return encoded
      },
    }
  )

/**
 * Re-keys a decoded map so that a text key holding a decimal integer -- `"0"`
 * -- is read as the integer `0`.
 *
 * ISO 18013-5 labels the retrieval-option maps with unsigned integers, but
 * implementations exist that write those labels as text strings, and a verifier
 * has to be able to read them. Keys that are not decimal integers are left
 * alone.
 */
export const coerceNumericKeys = (encodedStructure: unknown): unknown => {
  if (!(encodedStructure instanceof Map)) return encodedStructure

  const coerced = new Map<unknown, unknown>()

  for (const [key, value] of encodedStructure) {
    coerced.set(typeof key === 'string' && /^(0|[1-9]\d*)$/.test(key) ? Number(key) : key, value)
  }

  return coerced
}

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
