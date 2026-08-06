import { z } from 'zod'
import {
  buildStructure,
  type CborDecodeOptions,
  CborStructure,
  cborArray,
  cborDataItem,
  type DataItem,
  decodeBytes,
  fromEncoded,
} from '../../cbor'
import type { EncodedCoseKeyStructure } from '../../cose'
import { EDeviceKey } from './e-device-key'

const schema = cborArray([
  ['cipherSuiteIdentifier', z.number()],
  ['eDeviceKey', cborDataItem(EDeviceKey)],
])

export type SecurityStructure = [number, DataItem<EncodedCoseKeyStructure>]

export type SecurityOptions = {
  // TODO: enum
  cipherSuiteIdentifier: number
  eDeviceKey: EDeviceKey
}

export class Security extends CborStructure {
  public static override schema = schema

  public constructor(options: SecurityOptions) {
    super(
      buildStructure([
        ['cipherSuiteIdentifier', options.cipherSuiteIdentifier],
        ['eDeviceKey', options.eDeviceKey],
      ])
    )
  }

  public override encodedStructure(): SecurityStructure {
    return super.encodedStructure() as SecurityStructure
  }

  public get cipherSuiteIdentifier(): number {
    return this.structure.get('cipherSuiteIdentifier') as number
  }

  public get eDeviceKey(): EDeviceKey {
    return this.structure.get('eDeviceKey') as EDeviceKey
  }

  public static override fromEncodedStructure(encodedStructure: unknown): Security {
    return fromEncoded(Security, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): Security {
    return decodeBytes(Security, bytes, options)
  }
}
