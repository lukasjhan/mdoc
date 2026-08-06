import { type CborDecodeOptions, CborStructure, type SchemaBackedClass } from '../../cbor/cbor-structure.js'
import { cborDecode, cborEncode } from '../../cbor/parser.js'

export type ProtectedHeadersStructure = Uint8Array

export type ProtectedHeaderOptions = {
  protectedHeaders?: Map<unknown, unknown> | Uint8Array
}

/**
 * The COSE protected header bucket: a byte string wrapping an encoded header
 * map.
 *
 * The bytes are what the signature covers, so when they arrive off the wire
 * they are kept verbatim and handed back unchanged. Reproducing them by
 * re-encoding the parsed map would depend on the issuer having used the same
 * map-header widths and key order this library does -- which is not something
 * a verifier gets to assume.
 *
 * The map is parsed lazily, only when a caller reads a header.
 */
export class ProtectedHeaders extends CborStructure {
  private raw?: Uint8Array
  private parsed?: Map<unknown, unknown>

  public constructor(options: ProtectedHeaderOptions = {}) {
    super()

    if (options.protectedHeaders instanceof Uint8Array) {
      this.raw = options.protectedHeaders
    } else if (options.protectedHeaders instanceof Map) {
      this.parsed = options.protectedHeaders
    }
  }

  public get headers(): Map<unknown, unknown> | undefined {
    if (this.parsed) return this.parsed

    if (this.raw?.length) {
      this.parsed = cborDecode<Map<unknown, unknown>>(this.raw, { mapsAsObjects: false })
      return this.parsed
    }

    return undefined
  }

  public encodedStructure(): ProtectedHeadersStructure {
    return this.raw ?? cborEncode(this.parsed)
  }

  // Cast because this class builds itself rather than going through a schema,
  // and it is never extended.
  public static override fromEncodedStructure<T extends CborStructure>(
    this: SchemaBackedClass<T>,
    encodedStructure: unknown
  ): T {
    return new ProtectedHeaders({
      protectedHeaders: encodedStructure as Uint8Array | Map<unknown, unknown>,
    }) as unknown as T
  }

  public static override decode<T extends CborStructure>(
    this: SchemaBackedClass<T>,
    bytes: Uint8Array,
    _options?: CborDecodeOptions
  ): T {
    return new ProtectedHeaders({ protectedHeaders: bytes }) as unknown as T
  }
}
