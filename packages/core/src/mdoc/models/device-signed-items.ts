import { z } from 'zod'
import { CborStructure, cborDynamicMap } from '../../cbor'
import type { DataElementIdentifier } from './data-element-identifier'
import type { DataElementValue } from './data-element-value'

const schema = cborDynamicMap(z.string(), z.unknown())

export type DeviceSignedItemsStructure = Map<DataElementIdentifier, DataElementValue>

export type DeviceSignedItemsOptions = {
  deviceSignedItems: Map<DataElementIdentifier, DataElementValue>
}

export class DeviceSignedItems extends CborStructure {
  public static override schema = schema

  public constructor(options: DeviceSignedItemsOptions) {
    super(new Map(options.deviceSignedItems))
  }

  public get deviceSignedItems(): Map<DataElementIdentifier, DataElementValue> {
    return this.structure as Map<DataElementIdentifier, DataElementValue>
  }

  public override encodedStructure(): DeviceSignedItemsStructure {
    return super.encodedStructure() as DeviceSignedItemsStructure
  }
}
