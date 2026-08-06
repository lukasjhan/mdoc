import { base64, base64url } from '../utils/transformers'
import { DateOnly } from './models/date-only'

export type JsonValue = string | number | boolean | null | JsonValue[] | { [key: string]: JsonValue }

export type CborToJsonOptions = {
  /**
   * How a byte string is rendered.
   *
   * - `base64url` (default) -- the bare encoding, per RFC 4648 §5.
   * - `dataUri` -- `data:application/octet-stream;base64,<base64>`, convenient
   *   for dropping a portrait straight into an `<img src>`. The media type is
   *   a guess: CBOR carries no type alongside the bytes.
   */
  bytes?: 'base64url' | 'dataUri'
}

/**
 * Renders a decoded CBOR value as JSON.
 *
 * The conversion is lossy and deliberately so -- JSON has no byte string, no
 * integer-keyed map, and no date. Element values are left as decoded CBOR
 * everywhere else in this library; call this when you need to hand them to
 * something that speaks JSON.
 *
 * | CBOR                    | JSON                                        |
 * | ----------------------- | ------------------------------------------- |
 * | tstr                    | string                                      |
 * | uint / nint             | number                                      |
 * | bignum                  | decimal string (JSON has no bigint)         |
 * | non-finite float        | `null`, as `JSON.stringify` does            |
 * | bool                    | boolean                                     |
 * | null / undefined        | `null`                                      |
 * | bstr                    | base64url string, or a data URI             |
 * | array                   | array                                       |
 * | map                     | object; integer keys become decimal strings |
 * | #6.1004 full-date       | `"2026-02-19"`                              |
 * | #6.0 tdate              | `"2026-02-19T12:00:00Z"`, no fraction       |
 * | anything with `toJSON`  | whatever it returns, converted in turn      |
 *
 * Two consequences worth knowing:
 *
 * - **Map order can change.** JavaScript objects list integer-like keys first,
 *   so a map keyed `{"zeta", 1, "alpha", 0}` comes back as `{"0", "1", "zeta",
 *   "alpha"}`. Read the `Map` directly if order matters.
 * - **Distinct keys can collide.** A map holding both `1` and `"1"` loses one
 *   of them, since both render as `"1"`.
 */
export const cborToJson = (value: unknown, options?: CborToJsonOptions): JsonValue => {
  const asDataUri = options?.bytes === 'dataUri'

  const convert = (input: unknown): JsonValue => {
    if (input === null || input === undefined) return null

    switch (typeof input) {
      case 'string':
        return input
      case 'boolean':
        return input
      // JSON has no bigint, and JSON.stringify throws on one
      case 'bigint':
        return input.toString()
      case 'number':
        return Number.isFinite(input) ? input : null
    }

    if (input instanceof Uint8Array) {
      return asDataUri ? `data:application/octet-stream;base64,${base64.encode(input)}` : base64url.encode(input)
    }

    // Matches the tdate extension, which writes no fraction of a second
    if (input instanceof Date) return `${input.toISOString().split('.')[0]}Z`

    if (input instanceof DateOnly) return input.toISOString()

    if (Array.isArray(input)) return input.map(convert)

    if (input instanceof Map) {
      const object: Record<string, JsonValue> = {}

      for (const [key, entry] of input) {
        object[typeof key === 'string' ? key : String(key)] = convert(entry)
      }

      return object
    }

    if (typeof (input as { toJSON?: unknown }).toJSON === 'function') {
      return convert((input as { toJSON(): unknown }).toJSON())
    }

    if (typeof input === 'object') {
      const object: Record<string, JsonValue> = {}

      for (const [key, entry] of Object.entries(input)) {
        object[key] = convert(entry)
      }

      return object
    }

    // Functions and symbols cannot appear in decoded CBOR
    return null
  }

  return convert(value)
}
