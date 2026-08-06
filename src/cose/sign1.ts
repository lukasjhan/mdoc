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
import { CoseCertificateNotFoundError, CoseInvalidAlgorithmError, CosePayloadMustBeDefinedError } from './error.js'
import { Header, type SignatureAlgorithm } from './headers/defaults.js'
import { type ProtectedHeaderOptions, ProtectedHeaders } from './headers/protected-headers.js'
import { UnprotectedHeaders, type UnprotectedHeadersOptions } from './headers/unprotected-headers.js'
import { coseKeyToJwk } from './key/jwk.js'
import type { CoseKey } from './key/key.js'

export type Sign1Structure = [Uint8Array, Map<unknown, unknown>, Uint8Array | null, Uint8Array]

const schema = cborArray([
  ['protectedHeaders', cborStructure(ProtectedHeaders)],
  ['unprotectedHeaders', cborStructure(UnprotectedHeaders)],
  ['payload', z.union([z.instanceof(Uint8Array), z.null()])],
  ['signature', z.instanceof(Uint8Array)],
])

export type Sign1Options = {
  protectedHeaders?: ProtectedHeaders | ProtectedHeaderOptions['protectedHeaders']
  unprotectedHeaders?: UnprotectedHeaders | UnprotectedHeadersOptions['unprotectedHeaders']
  payload?: Uint8Array | null
  signature?: Uint8Array

  detachedContent?: Uint8Array
  externalAad?: Uint8Array
}

/** The inputs to the `Signature1` computation that are not themselves wire data. */
type Sign1Content = {
  detachedContent?: Uint8Array
  externalAad?: Uint8Array
}

/**
 * COSE_Sign1.
 *
 * The four wire elements are fixed once the object exists, so a structure that
 * has been decoded and verified cannot then be altered.
 *
 * `detachedContent` and `externalAad` are not wire data -- they are inputs to
 * the `Signature1` computation. They are fixed at construction, or carried onto
 * a copy by `withDetachedContent`, which is what lets `toBeSigned` be cached
 * with no invalidation logic at all.
 */
export class Sign1 extends CborStructure {
  public static tag = 18
  public static override schema = schema

  // Optional because a decoded structure is built without running the
  // constructor: bytes off the wire carry no detached content by definition.
  protected content?: Sign1Content
  private toBeSignedCache?: Uint8Array

  public constructor(options: Sign1Options) {
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
        ['signature', options.signature],
      ])
    )

    this.content = { detachedContent: options.detachedContent, externalAad: options.externalAad }
  }

  /** Narrows the base return type; the schema guarantees the four-element shape. */
  public override encodedStructure(): Sign1Structure {
    return super.encodedStructure() as Sign1Structure
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

  public get signature(): Uint8Array | undefined {
    return this.structure.get('signature') as Uint8Array | undefined
  }

  public get detachedContent(): Uint8Array | undefined {
    return this.content?.detachedContent
  }

  public get externalAad(): Uint8Array | undefined {
    return this.content?.externalAad
  }

  /**
   * Produces a copy of this structure with different transient content and,
   * optionally, a different wire structure. Used rather than assignment so that
   * the receiver stays exactly as it was handed out.
   */
  protected derive(structure: CborMap, content: Sign1Content): this {
    const copy = Object.create(Object.getPrototypeOf(this)) as this & { structure: CborMap; content: Sign1Content }

    copy.structure = structure
    copy.content = content

    return copy
  }

  /**
   * A copy carrying the detached content the signature was made over. A
   * detached signature's content arrives separately from the structure, so it
   * cannot be known when the structure is decoded.
   */
  public withDetachedContent(detachedContent: Uint8Array): this {
    return this.derive(this.structure, { ...this.content, detachedContent })
  }

  protected get transientContent(): Sign1Content {
    return this.content ?? {}
  }

  public get certificateChain() {
    return this.x5chain ?? []
  }

  public get certificate() {
    const [certificate] = this.certificateChain

    if (!certificate) {
      throw new CoseCertificateNotFoundError()
    }

    return certificate
  }

  public getIssuingCountry(ctx: Pick<MdocContext, 'x509'>) {
    const countryName = ctx.x509.getIssuerNameField({
      certificate: this.certificate,
      field: 'C',
    })[0]

    return countryName
  }

  public getIssuingStateOrProvince(ctx: Pick<MdocContext, 'x509'>) {
    const stateOrProvince = ctx.x509.getIssuerNameField({
      certificate: this.certificate,
      field: 'ST',
    })[0]

    return stateOrProvince
  }

  public get toBeSigned() {
    if (this.toBeSignedCache) return this.toBeSignedCache

    const payload = this.detachedContent ?? this.payload

    if (!payload) {
      throw new CosePayloadMustBeDefinedError()
    }

    this.toBeSignedCache = cborEncode([
      'Signature1',
      this.protectedHeaders.encodedStructure(),
      this.externalAad ?? new Uint8Array(),
      payload,
    ])

    return this.toBeSignedCache
  }

  public get signatureAlgorithmName(): string {
    const algorithm = (this.protectedHeaders.headers?.get(Header.Algorithm) ??
      this.unprotectedHeaders.headers?.get(Header.Algorithm)) as SignatureAlgorithm | undefined

    if (!algorithm) {
      throw new CoseInvalidAlgorithmError()
    }

    const algorithmName = coseKeyToJwk.algorithm(algorithm)

    if (!algorithmName) {
      throw new CoseInvalidAlgorithmError()
    }

    return algorithmName
  }

  public get x5chain() {
    const x5chain =
      (this.protectedHeaders.headers?.get(Header.X5Chain) as Uint8Array | Uint8Array[] | undefined) ??
      (this.unprotectedHeaders.headers?.get(Header.X5Chain) as Uint8Array | Uint8Array[] | undefined)

    if (!x5chain?.[0]) {
      return undefined
    }

    return Array.isArray(x5chain) ? x5chain : [x5chain]
  }

  /**
   * Signs the structure and returns the signed copy. The receiver is unchanged,
   * so a structure never acquires a signature after the fact.
   */
  public async sign(options: { signingKey: CoseKey }, ctx: Pick<MdocContext, 'cose'>): Promise<this> {
    if (!this.payload && !this.detachedContent) {
      throw new CosePayloadMustBeDefinedError()
    }

    const signature = await ctx.cose.sign1.sign({ sign1: this, key: options.signingKey })

    return this.derive(new Map(this.structure).set('signature', signature), this.transientContent)
  }

  public async verifySignature(options: { key?: CoseKey }, ctx: Pick<MdocContext, 'cose' | 'x509'>) {
    const publicKey =
      options.key ??
      (await ctx.x509.getPublicKey({
        certificate: this.certificate,
        alg: this.signatureAlgorithmName,
      }))

    return await ctx.cose.sign1.verify({
      sign1: this,
      key: publicKey,
    })
  }

  public static fromEncodedSignature1(signature1: Uint8Array) {
    const structure = cborDecode<[string, Uint8Array, Uint8Array, Uint8Array]>(signature1, { mapsAsObjects: false })

    return new Sign1({
      protectedHeaders: ProtectedHeaders.decode(structure[1]),
      externalAad: structure[2],
      payload: structure[3],
    })
  }

  /**
   * Accepts the structure tagged or bare. A tag-18 structure is turned into a
   * `Sign1` by the extension below, so its encoded form is taken back out and
   * validated against `this`, which keeps a subclass decoding as itself.
   */
  public static override decode<T extends CborStructure>(
    this: SchemaBackedClass<T>,
    bytes: Uint8Array,
    options?: CborDecodeOptions
  ): T {
    const structure = cborDecode<unknown>(bytes, options)

    return fromEncoded(this, structure instanceof Sign1 ? structure.encodedStructure() : structure)
  }
}

addExtension({
  Class: Sign1,
  tag: Sign1.tag,
  // TODO: why is the tag not being used?
  encode(instance: Sign1, encodeFn: (obj: unknown) => Uint8Array) {
    return encodeFn(instance)
  },
  // Wrapped rather than passed by reference: the static reads `this`.
  decode: (structure: unknown) => Sign1.fromEncodedStructure(structure),
})
