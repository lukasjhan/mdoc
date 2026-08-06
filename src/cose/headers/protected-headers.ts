import { type CborDecodeOptions, CborStructure } from '../../cbor/cbor-structure.js'
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

  public static override fromEncodedStructure(encodedStructure: unknown): ProtectedHeaders {
    return new ProtectedHeaders({ protectedHeaders: encodedStructure as Uint8Array | Map<unknown, unknown> })
  }

  public static override decode(bytes: Uint8Array, _options?: CborDecodeOptions): ProtectedHeaders {
    return new ProtectedHeaders({ protectedHeaders: bytes })
  }
}
