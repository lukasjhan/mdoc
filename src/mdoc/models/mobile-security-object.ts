import { z } from 'zod'
import { buildStructure, CborStructure, cborMap, cborStructure } from '../../cbor'
import type { DigestAlgorithm } from '../../cose'
import { DeviceKeyInfo } from './device-key-info'
import type { DocType } from './doctype'
import { Status, type StatusOptions } from './status'
import { ValidityInfo } from './validity-info'
import { ValueDigests } from './value-digests'

// Declaration order is wire order for structures built in memory, so it
// matches what this library has always emitted.
const schema = cborMap([
  ['version', z.string()],
  ['digestAlgorithm', z.string()],
  ['valueDigests', cborStructure(ValueDigests)],
  ['deviceKeyInfo', cborStructure(DeviceKeyInfo)],
  ['docType', z.string()],
  ['validityInfo', cborStructure(ValidityInfo)],
  ['status', cborStructure(Status).optional()],
])

export type MobileSecurityObjectOptions = {
  version?: string
  digestAlgorithm: DigestAlgorithm
  docType: DocType
  valueDigests: ValueDigests
  validityInfo: ValidityInfo
  deviceKeyInfo: DeviceKeyInfo
  status?: Status | StatusOptions
}

export class MobileSecurityObject extends CborStructure {
  public static override schema = schema

  public constructor(options: MobileSecurityObjectOptions) {
    super(
      buildStructure([
        ['version', options.version ?? '1.0'],
        ['digestAlgorithm', options.digestAlgorithm],
        ['valueDigests', options.valueDigests],
        ['deviceKeyInfo', options.deviceKeyInfo],
        ['docType', options.docType],
        ['validityInfo', options.validityInfo],
        ['status', options.status instanceof Status ? options.status : options.status && new Status(options.status)],
      ])
    )
  }

  public get version(): string {
    return this.structure.get('version') as string
  }

  public get digestAlgorithm(): DigestAlgorithm {
    return this.structure.get('digestAlgorithm') as DigestAlgorithm
  }

  public get docType(): string {
    return this.structure.get('docType') as string
  }

  public get valueDigests(): ValueDigests {
    return this.structure.get('valueDigests') as ValueDigests
  }

  public get deviceKeyInfo(): DeviceKeyInfo {
    return this.structure.get('deviceKeyInfo') as DeviceKeyInfo
  }

  public get validityInfo(): ValidityInfo {
    return this.structure.get('validityInfo') as ValidityInfo
  }

  public get status(): Status | undefined {
    return this.structure.get('status') as Status | undefined
  }
}
