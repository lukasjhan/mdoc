import { buildStructure, CborStructure, cborDataItem, cborMap, cborStructure, type DataItem } from '../../cbor'
import { DeviceAuth, type DeviceAuthStructure } from './device-auth'
import { DeviceNamespaces, type DeviceNamespacesStructure } from './device-namespaces'

const schema = cborMap([
  ['nameSpaces', cborDataItem(DeviceNamespaces)],
  ['deviceAuth', cborStructure(DeviceAuth)],
])

export type DeviceSignedStructure = {
  nameSpaces: DataItem<DeviceNamespacesStructure>
  deviceAuth: DeviceAuthStructure
}

export type DeviceSignedOptions = {
  deviceNamespaces: DeviceNamespaces
  deviceAuth: DeviceAuth
}

export class DeviceSigned extends CborStructure {
  public static override schema = schema

  public constructor(options: DeviceSignedOptions) {
    super(
      buildStructure([
        ['nameSpaces', options.deviceNamespaces],
        ['deviceAuth', options.deviceAuth],
      ])
    )
  }

  public get deviceNamespaces(): DeviceNamespaces {
    return this.structure.get('nameSpaces') as DeviceNamespaces
  }

  public get deviceAuth(): DeviceAuth {
    return this.structure.get('deviceAuth') as DeviceAuth
  }

  public override encodedStructure(): DeviceSignedStructure {
    return super.encodedStructure() as DeviceSignedStructure
  }
}
