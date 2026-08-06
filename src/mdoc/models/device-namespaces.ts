import { z } from 'zod'
import { CborStructure, cborDynamicMap, cborStructure } from '../../cbor'
import { DeviceSignedItems, type DeviceSignedItemsStructure } from './device-signed-items'
import type { Namespace } from './namespace'

const schema = cborDynamicMap(z.string(), cborStructure(DeviceSignedItems))

export type DeviceNamespacesStructure = Map<Namespace, DeviceSignedItemsStructure>

export type DeviceNamespacesOptions = {
  deviceNamespaces: Map<Namespace, DeviceSignedItems>
}

export class DeviceNamespaces extends CborStructure {
  public static override schema = schema

  public constructor(options: DeviceNamespacesOptions) {
    super(new Map(options.deviceNamespaces))
  }

  public get deviceNamespaces(): Map<Namespace, DeviceSignedItems> {
    return this.structure as Map<Namespace, DeviceSignedItems>
  }

  public override encodedStructure(): DeviceNamespacesStructure {
    return super.encodedStructure() as DeviceNamespacesStructure
  }
}
