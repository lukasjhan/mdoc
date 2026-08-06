import type { Options as CborXParserOptions } from 'cbor-x'
import { z } from 'zod'
import { DataItem } from './data-item'
import { cborDecode, cborEncode } from './parser'
import type { CborMap } from './schema'

export type CborEncodeOptions = {
  asDataItem?: boolean
}

export type CborDecodeOptions = CborXParserOptions

/**
 * Thrown when a CBOR structure does not match the schema its model declares.
 * Carries the underlying issues so a caller can tell a malformed document
 * apart from an unsupported one.
 */
export class CborSchemaError extends Error {
  public constructor(
    public readonly structureName: string,
    public readonly issues: readonly z.core.$ZodIssue[]
  ) {
    const detail = issues.map((issue) => `${issue.path.join('.') || '<root>'}: ${issue.message}`).join('; ')
    super(`Invalid ${structureName}: ${detail}`)
  }
}

/**
 * Base class for every CBOR-backed model.
 *
 * A subclass declares its wire format once as a `static schema`, and encoding,
 * decoding and validation all follow from it. The decoded map is held in
 * `structure`; subclasses expose it through getters, so a model cannot be
 * mutated after it has been validated.
 *
 * Models that have not been migrated yet override `encodedStructure`,
 * `fromEncodedStructure` and `decode` by hand and never touch `structure`.
 * Both styles coexist so the migration can proceed model by model.
 */
export abstract class CborStructure {
  protected structure: CborMap

  public constructor(structure?: CborMap) {
    this.structure = structure ?? new Map()
  }

  /** The wire format of this structure. Subclasses override to declare it. */
  public static schema?: z.ZodType

  public encodedStructure(): unknown {
    const model = this.constructor as typeof CborStructure

    if (!model.schema) {
      throw new Error(`${model.name} declares no schema and does not override encodedStructure`)
    }

    const result = z.safeEncode(model.schema, this.structure)

    if (!result.success) throw new CborSchemaError(model.name, result.error.issues)

    return result.data
  }

  public encode(options?: CborEncodeOptions): Uint8Array {
    const structure = this.encodedStructure()

    return cborEncode(options?.asDataItem ? DataItem.fromData(structure) : structure)
  }

  public static fromEncodedStructure(_encodedStructure: unknown): CborStructure {
    throw new Error('fromEncodedStructure must be implemented')
  }

  public static decode(_bytes: Uint8Array, _options?: CborDecodeOptions): CborStructure {
    throw new Error('decode must be implemented')
  }
}

type SchemaBackedClass<T extends CborStructure> = {
  new (...args: never[]): T
  prototype: T
  schema?: z.ZodType
  name: string
}

/**
 * Builds a model instance from an already `cborDecode`d structure, validating
 * it against the model's schema.
 *
 * The decoded map is the model's final state, so the options-taking constructor
 * is bypassed rather than reconstructed from it.
 */
export const fromEncoded = <T extends CborStructure>(Class: SchemaBackedClass<T>, encodedStructure: unknown): T => {
  if (!Class.schema) throw new Error(`${Class.name} declares no schema`)

  const result = z.safeDecode(Class.schema, encodedStructure)

  if (!result.success) throw new CborSchemaError(Class.name, result.error.issues)

  const instance = Object.create(Class.prototype) as T & { structure: CborMap }
  instance.structure = result.data as CborMap

  return instance
}

/** Decodes CBOR bytes into a model instance, validating against its schema. */
export const decodeBytes = <T extends CborStructure>(
  Class: SchemaBackedClass<T>,
  bytes: Uint8Array,
  options?: CborDecodeOptions
): T => fromEncoded(Class, cborDecode(bytes, { ...(options ?? {}), mapsAsObjects: false }))
