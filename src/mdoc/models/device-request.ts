import { z } from 'zod'
import { buildStructure, CborStructure, cborMap, cborStructure } from '../../cbor'
import { DocRequest, type DocRequestStructure } from './doc-request'

const schema = cborMap([
  ['version', z.string()],
  ['docRequests', z.array(cborStructure(DocRequest))],
])

export type DeviceRequestStructure = {
  version: string
  docRequests: Array<DocRequestStructure>
}

export type DeviceRequestOptions = {
  version?: string
  docRequests: Array<DocRequest>
}

export class DeviceRequest extends CborStructure {
  public static override schema = schema

  public constructor(options: DeviceRequestOptions) {
    super(
      buildStructure([
        ['version', options.version ?? '1.0'],
        ['docRequests', options.docRequests],
      ])
    )
  }

  public get version(): string {
    return this.structure.get('version') as string
  }

  public get docRequests(): Array<DocRequest> {
    return this.structure.get('docRequests') as Array<DocRequest>
  }

  public override encodedStructure(): DeviceRequestStructure {
    return super.encodedStructure() as DeviceRequestStructure
  }
}
