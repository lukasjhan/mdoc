import { CoseKey, type CoseKeyOptions, type EncodedCoseKeyStructure } from '../../cose/key/key'

export type EDeviceKeyStructure = EncodedCoseKeyStructure

export type EDeviceKeyOptions = CoseKeyOptions

export class EDeviceKey extends CoseKey {}
