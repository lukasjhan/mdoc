import { concatBytes } from '@noble/curves/utils.js'
import { z } from 'zod'
import { buildStructure, type CborDecodeOptions, CborStructure, cborMap, decodeBytes, fromEncoded } from '../../cbor'
import {
  CoseDNotDefinedError,
  CoseInvalidKtyForRawError,
  CoseInvalidValueForKtyError,
  CoseKeyTypeNotSupportedForPrivateKeyExtractionError,
  CoseKNotDefinedError,
  CoseXNotDefinedError,
  CoseYNotDefinedError,
} from '../error'
import type { Curve } from './curve'
import { coseKeyToJwk, coseOptionsJwkMap, jwkCoseOptionsMap, jwkToCoseKey } from './jwk'
import type { KeyOps } from './key-operation'
import { KeyType } from './key-type'

export enum CoseKeyParameter {
  KeyType = 1,
  KeyId = 2,
  Algorithm = 3,
  KeyOps = 4,
  BaseIv = 5,

  // EC Key or Oct with K
  CurveOrK = -1,
  X = -2,
  Y = -3,
  D = -4,
}

export type EncodedCoseKeyStructure = Map<unknown, unknown>

/**
 * RFC 8152 gives label -1 two meanings: the curve for EC2 and OKP keys, and the
 * key material for Symmetric ones. One slot, so `curve` and `k` read from it and
 * decide by key type.
 */
const schema = cborMap([
  [CoseKeyParameter.KeyType, z.union([z.number(), z.string()])],
  // RFC 8152 defines kid as a bstr, but implementations in the wild put a text
  // string there -- the Animo test vector carries a UUID. Reading both keeps
  // those credentials verifiable; this library still writes bytes.
  [CoseKeyParameter.KeyId, z.union([z.instanceof(Uint8Array), z.string()]).optional()],
  [CoseKeyParameter.Algorithm, z.union([z.string(), z.number()]).optional()],
  [CoseKeyParameter.KeyOps, z.array(z.union([z.string(), z.number()])).optional()],
  [CoseKeyParameter.BaseIv, z.instanceof(Uint8Array).optional()],
  [CoseKeyParameter.CurveOrK, z.union([z.number(), z.string(), z.instanceof(Uint8Array)]).optional()],
  [CoseKeyParameter.X, z.instanceof(Uint8Array).optional()],
  [CoseKeyParameter.Y, z.instanceof(Uint8Array).optional()],
  [CoseKeyParameter.D, z.instanceof(Uint8Array).optional()],
])

export type CoseKeyOptions = {
  keyType: KeyType | string
  keyId?: Uint8Array
  algorithm?: string | number
  keyOps?: Array<KeyOps | string>
  baseIv?: Uint8Array

  curve?: Curve
  x?: Uint8Array
  y?: Uint8Array

  d?: Uint8Array

  k?: Uint8Array
}

export class CoseKey extends CborStructure {
  public static override schema = schema

  public constructor(options: CoseKeyOptions) {
    super(
      buildStructure([
        [CoseKeyParameter.KeyType, options.keyType],
        [CoseKeyParameter.KeyId, options.keyId],
        [CoseKeyParameter.Algorithm, options.algorithm],
        [CoseKeyParameter.KeyOps, options.keyOps],
        [CoseKeyParameter.BaseIv, options.baseIv],
        [CoseKeyParameter.CurveOrK, options.curve ?? options.k],
        [CoseKeyParameter.X, options.x],
        [CoseKeyParameter.Y, options.y],
        [CoseKeyParameter.D, options.d],
      ])
    )
  }

  public override encodedStructure(): EncodedCoseKeyStructure {
    return super.encodedStructure() as EncodedCoseKeyStructure
  }

  public get keyType(): KeyType | string {
    return this.structure.get(CoseKeyParameter.KeyType) as KeyType | string
  }

  /** A `string` only when the source encoded a non-conformant text-string kid. */
  public get keyId(): Uint8Array | string | undefined {
    return this.structure.get(CoseKeyParameter.KeyId) as Uint8Array | string | undefined
  }

  public get algorithm(): string | number | undefined {
    return this.structure.get(CoseKeyParameter.Algorithm) as string | number | undefined
  }

  public get keyOps(): Array<KeyOps | string> | undefined {
    return this.structure.get(CoseKeyParameter.KeyOps) as Array<KeyOps | string> | undefined
  }

  public get baseIv(): Uint8Array | undefined {
    return this.structure.get(CoseKeyParameter.BaseIv) as Uint8Array | undefined
  }

  public get curve(): Curve | undefined {
    if (this.keyType === KeyType.Oct) return undefined

    return this.structure.get(CoseKeyParameter.CurveOrK) as Curve | undefined
  }

  public get k(): Uint8Array | undefined {
    if (this.keyType !== KeyType.Oct) return undefined

    return this.structure.get(CoseKeyParameter.CurveOrK) as Uint8Array | undefined
  }

  public get x(): Uint8Array | undefined {
    return this.structure.get(CoseKeyParameter.X) as Uint8Array | undefined
  }

  public get y(): Uint8Array | undefined {
    return this.structure.get(CoseKeyParameter.Y) as Uint8Array | undefined
  }

  public get d(): Uint8Array | undefined {
    return this.structure.get(CoseKeyParameter.D) as Uint8Array | undefined
  }

  public static fromJwk(jwk: Record<string, unknown>) {
    if (!('kty' in jwk)) {
      throw new CoseInvalidValueForKtyError('JWK does not contain required kty value')
    }

    const options = Object.entries(jwk).reduce(
      (prev, [key, value]) => ({
        ...prev,
        [jwkCoseOptionsMap[key] ?? key]:
          typeof jwkToCoseKey[key as keyof typeof jwkToCoseKey] === 'function'
            ? jwkToCoseKey[key as keyof typeof jwkToCoseKey](value)
            : undefined,
      }),
      {} as CoseKeyOptions
    )

    return new CoseKey(options)
  }

  public static override fromEncodedStructure(encodedStructure: unknown): CoseKey {
    assertKeyType(encodedStructure)

    return fromEncoded(CoseKey, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): CoseKey {
    return decodeBytes(CoseKey, bytes, options)
  }

  public get publicKey() {
    if (this.keyType !== KeyType.Ec) {
      throw new CoseInvalidKtyForRawError()
    }

    if (!this.x) {
      throw new CoseXNotDefinedError()
    }

    if (!this.y) {
      throw new CoseYNotDefinedError()
    }

    return concatBytes(Uint8Array.from([0x04]), this.x, this.y)
  }

  public get privateKey() {
    if (this.keyType === KeyType.Ec) {
      if (!this.d) {
        throw new CoseDNotDefinedError()
      }

      return this.d
    }

    if (this.keyType === KeyType.Oct) {
      if (!this.k) {
        throw new CoseKNotDefinedError()
      }

      return this.k
    }

    throw new CoseKeyTypeNotSupportedForPrivateKeyExtractionError()
  }

  public get jwk(): Record<string, unknown> {
    // Enumerated rather than read off the instance: the values live in the
    // decoded structure now, not as own properties.
    const claims: Record<string, unknown> = {
      keyType: this.keyType,
      keyId: this.keyId,
      algorithm: this.algorithm,
      keyOps: this.keyOps,
      baseIv: this.baseIv,
      curve: this.curve,
      x: this.x,
      y: this.y,
      d: this.d,
      k: this.k,
    }

    return Object.entries(claims).reduce(
      (prev, [key, value]) => ({
        ...prev,
        [coseOptionsJwkMap[key] ?? key]:
          typeof coseKeyToJwk[key as keyof typeof coseKeyToJwk] === 'function'
            ? // @ts-ignore
              coseKeyToJwk[key as keyof typeof coseKeyToJwk](value)
            : undefined,
      }),
      {}
    )
  }
}

/** Preserves the dedicated error this class has always thrown for a missing kty. */
export const assertKeyType = (encodedStructure: unknown) => {
  if (encodedStructure instanceof Map && !encodedStructure.get(CoseKeyParameter.KeyType)) {
    throw new CoseInvalidValueForKtyError()
  }
}
