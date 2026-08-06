import { z } from 'zod'
import { buildStructure, CborStructure, cborArray, cborDataItem, type DataItem } from '../../cbor'
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
}
