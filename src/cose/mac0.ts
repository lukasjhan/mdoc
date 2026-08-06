import { z } from 'zod'
import {
  addExtension,
  buildStructure,
  type CborDecodeOptions,
  type CborMap,
  CborStructure,
  cborArray,
  cborDecode,
  cborEncode,
  cborStructure,
  fromEncoded,
  type SchemaBackedClass,
} from '../cbor/index.js'
import type { MdocContext } from '../context.js'
import { SessionTranscript } from '../mdoc/models/session-transcript.js'
import { CoseInvalidAlgorithmError, CosePayloadMustBeDefinedError } from './error.js'
import { Header, type MacAlgorithm } from './headers/defaults.js'
import { type ProtectedHeaderOptions, ProtectedHeaders } from './headers/protected-headers.js'
import { UnprotectedHeaders, type UnprotectedHeadersOptions } from './headers/unprotected-headers.js'
import { coseKeyToJwk } from './key/jwk.js'
import type { CoseKey } from './key/key.js'

export type Mac0Structure = [Uint8Array, Map<unknown, unknown>, Uint8Array | null, Uint8Array]

const schema = cborArray([
  ['protectedHeaders', cborStructure(ProtectedHeaders)],
  ['unprotectedHeaders', cborStructure(UnprotectedHeaders)],
  ['payload', z.union([z.instanceof(Uint8Array), z.null()])],
  ['tag', z.instanceof(Uint8Array)],
])

export type Mac0Options = {
  protectedHeaders: ProtectedHeaders | ProtectedHeaderOptions['protectedHeaders']
  unprotectedHeaders: UnprotectedHeaders | UnprotectedHeadersOptions['unprotectedHeaders']
  payload?: Uint8Array | null
  tag?: Uint8Array
  externalAad?: Uint8Array
  detachedContent?: Uint8Array
}

/** The inputs to the `MAC0` computation that are not themselves wire data. */
type Mac0Content = {
  detachedContent?: Uint8Array
  externalAad?: Uint8Array
}

/**
 * COSE_Mac0.
 *
 * As with `Sign1`, the wire elements are fixed once the object exists and the
 * detached content is carried alongside rather than assigned into it.
 */
export class Mac0 extends CborStructure {
  public static tag = 17
  public static override schema = schema

  // Optional because a decoded structure is built without running the
  // constructor: bytes off the wire carry no detached content by definition.
  protected content?: Mac0Content
  private toBeAuthenticatedCache?: Uint8Array

  public constructor(options: Mac0Options) {
    super(
      buildStructure([
        [
          'protectedHeaders',
          options.protectedHeaders instanceof ProtectedHeaders
            ? options.protectedHeaders
            : new ProtectedHeaders({ protectedHeaders: options.protectedHeaders }),
        ],
        [
          'unprotectedHeaders',
          options.unprotectedHeaders instanceof UnprotectedHeaders
            ? options.unprotectedHeaders
            : new UnprotectedHeaders({ unprotectedHeaders: options.unprotectedHeaders }),
        ],
        ['payload', options.payload ?? null],
        ['tag', options.tag],
      ])
    )

    this.content = { detachedContent: options.detachedContent, externalAad: options.externalAad }
  }

  /** Narrows the base return type; the schema guarantees the four-element shape. */
  public override encodedStructure(): Mac0Structure {
    return super.encodedStructure() as Mac0Structure
  }

  public get protectedHeaders(): ProtectedHeaders {
    return this.structure.get('protectedHeaders') as ProtectedHeaders
  }

  public get unprotectedHeaders(): UnprotectedHeaders {
    return this.structure.get('unprotectedHeaders') as UnprotectedHeaders
  }

  public get payload(): Uint8Array | null {
    return (this.structure.get('payload') as Uint8Array | null | undefined) ?? null
  }

  public get tag(): Uint8Array | undefined {
    return this.structure.get('tag') as Uint8Array | undefined
  }

  public get detachedContent(): Uint8Array | undefined {
    return this.content?.detachedContent
  }

  public get externalAad(): Uint8Array | undefined {
    return this.content?.externalAad
  }

  protected get transientContent(): Mac0Content {
    return this.content ?? {}
  }

  protected derive(structure: CborMap, content: Mac0Content): this {
    const copy = Object.create(Object.getPrototypeOf(this)) as this & { structure: CborMap; content: Mac0Content }

    copy.structure = structure
    copy.content = content

    return copy
  }

  /** A copy carrying the detached content the tag was computed over. */
  public withDetachedContent(detachedContent: Uint8Array): this {
    return this.derive(this.structure, { ...this.transientContent, detachedContent })
  }

  public get toBeAuthenticated() {
    if (this.toBeAuthenticatedCache) return this.toBeAuthenticatedCache

    const payload = this.detachedContent ?? this.payload

    if (!payload) {
      throw new CosePayloadMustBeDefinedError()
    }

    const toBeAuthenticated: Array<unknown> = ['MAC0', this.protectedHeaders]

    if (this.externalAad) toBeAuthenticated.push(this.externalAad)

    toBeAuthenticated.push(payload)

    this.toBeAuthenticatedCache = cborEncode(toBeAuthenticated)

    return this.toBeAuthenticatedCache
  }

  public get signatureAlgorithmName(): MacAlgorithm {
    const algorithm = (this.protectedHeaders.headers?.get(Header.Algorithm) ??
      this.unprotectedHeaders.headers?.get(Header.Algorithm)) as MacAlgorithm | undefined

    if (!algorithm) {
      throw new CoseInvalidAlgorithmError()
    }

    const algorithmName = coseKeyToJwk.algorithm(algorithm)

    if (!algorithmName) {
      throw new CoseInvalidAlgorithmError()
    }

    return algorithmName
  }

  /**
   * Computes the tag and returns the tagged copy. The receiver is unchanged,
   * mirroring `Sign1.sign`.
   */
  public async authenticate(
    options: { privateKey: CoseKey; ephemeralKey: CoseKey; sessionTranscript: SessionTranscript | Uint8Array },
    ctx: Pick<MdocContext, 'crypto' | 'cose'>
  ): Promise<this> {
    const ephemeralMacKey = await ctx.crypto.calculateEphemeralMacKey({
      privateKey: options.privateKey.encode(),
      publicKey: options.ephemeralKey.encode(),
      sessionTranscriptBytes:
        options.sessionTranscript instanceof SessionTranscript
          ? options.sessionTranscript.encode({ asDataItem: true })
          : options.sessionTranscript,
      info: 'EMacKey',
    })

    const tag = await ctx.cose.mac0.sign({ mac0: this, key: ephemeralMacKey })

    return this.derive(new Map(this.structure).set('tag', tag), this.transientContent)
  }

  /**
   * Accepts the structure tagged or bare. A tag-17 structure is turned into a
   * `Mac0` by the extension below, so its encoded form is taken back out and
   * validated against `this`, which keeps a subclass decoding as itself.
   */
  public static override decode<T extends CborStructure>(
    this: SchemaBackedClass<T>,
    bytes: Uint8Array,
    options?: CborDecodeOptions
  ): T {
    const structure = cborDecode<unknown>(bytes, options)

    return fromEncoded(this, structure instanceof Mac0 ? structure.encodedStructure() : structure)
  }
}

addExtension({
  Class: Mac0,
  tag: Mac0.tag,
  // TODO: why is the tag not being used?
  encode(instance: Mac0, encodeFn: (obj: unknown) => Uint8Array) {
    return encodeFn(instance.encodedStructure())
  },
  // Wrapped rather than passed by reference: the static reads `this`.
  decode: (structure: unknown) => Mac0.fromEncodedStructure(structure),
})
