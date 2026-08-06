import { z } from 'zod'
import {
  buildStructure,
  type CborDecodeOptions,
  type CborEncodeOptions,
  type CborKey,
  CborStructure,
  cborEncode,
  cborMap,
  cborStructure,
  coerceNumericKeys,
  DataItem,
  decodeBytes,
  fromEncoded,
} from '../../cbor'
import { DeviceRetrievalMethod, type DeviceRetrievalMethodStructure } from './device-retrieval-method'
import { ProtocolInfo, type ProtocolInfoStructure } from './protocol-info'
import { Security, type SecurityStructure } from './security'
import { ServerRetrievalMethod, type ServerRetrievalMethodStructure } from './server-retrieval-method'

// ISO 18013-5 keys DeviceEngagement by unsigned integer, and leaves the range
// above 4 open. Keys the schema does not name pass through untouched, which is
// what the previous `extra` bag was doing by hand.
const schema = cborMap([
  [0, z.string()],
  [1, cborStructure(Security)],
  [2, z.array(cborStructure(DeviceRetrievalMethod)).optional()],
  [3, z.array(cborStructure(ServerRetrievalMethod)).optional()],
  [4, cborStructure(ProtocolInfo).optional()],
])

export type DeviceEngagementStructure = {
  0: string
  1: SecurityStructure
  2?: Array<DeviceRetrievalMethodStructure>
  3?: Array<ServerRetrievalMethodStructure>
  4?: ProtocolInfoStructure
} & Record<number, unknown>

export type DeviceEngagementOptions = {
  version: string
  security: Security
  deviceRetrievalMethods?: Array<DeviceRetrievalMethod>
  serverRetrievalMethods?: Array<ServerRetrievalMethod>
  protocolInfo?: ProtocolInfo
  extra?: Record<string, unknown>
}

export class DeviceEngagement extends CborStructure {
  public static override schema = schema

  /**
   * Original CBOR bytes, kept when decoding so that encode() reproduces them.
   * The session keys derive over these, so they cannot be rebuilt by
   * re-encoding. A plain property rather than a private field: decoded
   * structures are built without running the constructor.
   */
  protected rawBytes?: Uint8Array

  public constructor(options: DeviceEngagementOptions) {
    super(
      buildStructure([
        [0, options.version],
        [1, options.security],
        [2, options.deviceRetrievalMethods],
        [3, options.serverRetrievalMethods],
        [4, options.protocolInfo],
        ...Object.entries(options.extra ?? {}).map(([key, value]) => [Number(key), value] as [CborKey, unknown]),
      ])
    )
  }

  public get version(): string {
    return this.structure.get(0) as string
  }

  public get security(): Security {
    return this.structure.get(1) as Security
  }

  public get deviceRetrievalMethods(): Array<DeviceRetrievalMethod> | undefined {
    return this.structure.get(2) as Array<DeviceRetrievalMethod> | undefined
  }

  public get serverRetrievalMethods(): Array<ServerRetrievalMethod> | undefined {
    return this.structure.get(3) as Array<ServerRetrievalMethod> | undefined
  }

  public get protocolInfo(): ProtocolInfo | undefined {
    return this.structure.get(4) as ProtocolInfo | undefined
  }

  /** Members outside the range this class models, preserved across a round-trip. */
  public get extra(): Record<string, unknown> {
    const extra: Record<string, unknown> = {}

    for (const [key, value] of this.structure) {
      if (![0, 1, 2, 3, 4].includes(key as number)) extra[String(key)] = value
    }

    return extra
  }

  public override encodedStructure(): DeviceEngagementStructure {
    return super.encodedStructure() as unknown as DeviceEngagementStructure
  }

  public override encode(options?: CborEncodeOptions): Uint8Array {
    if (this.rawBytes) {
      if (options?.asDataItem) {
        return cborEncode(new DataItem({ buffer: this.rawBytes }))
      }
      return this.rawBytes
    }
    return super.encode(options)
  }

  public static override fromEncodedStructure(encodedStructure: unknown): DeviceEngagement {
    return fromEncoded(DeviceEngagement, coerceNumericKeys(encodedStructure))
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceEngagement {
    const engagement = decodeBytes(DeviceEngagement, bytes, options)
    engagement.rawBytes = bytes
    return engagement
  }
}
