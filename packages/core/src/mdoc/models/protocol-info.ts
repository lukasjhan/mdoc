import { CborStructure, type SchemaBackedClass } from '../../cbor'
import { CborEncodeError } from '../../cbor/error'

export type ProtocolInfoStructure = never

export class ProtocolInfo extends CborStructure {
  public encodedStructure(): ProtocolInfoStructure {
    throw new CborEncodeError('protocolInfo is RFU (reserved for future use)')
  }

  public static override fromEncodedStructure<T extends CborStructure>(
    this: SchemaBackedClass<T>,
    _encodedStructure: unknown
  ): T {
    throw new CborEncodeError('protocolInfo is RFU (reserved for future use)')
  }
}
