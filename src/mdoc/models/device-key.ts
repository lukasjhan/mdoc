import { CoseKey, type CoseKeyOptions, type EncodedCoseKeyStructure } from '../../cose/key/key'

export type DeviceKeyStructure = EncodedCoseKeyStructure

export type DeviceKeyOptions = CoseKeyOptions

export class DeviceKey extends CoseKey {}
