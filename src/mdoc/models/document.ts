import { z } from 'zod'
import {
  buildStructure,
  type CborDecodeOptions,
  CborStructure,
  cborMap,
  cborStructure,
  decodeBytes,
  fromEncoded,
} from '../../cbor'
import { DeviceSigned, type DeviceSignedStructure } from './device-signed'
import type { DocType } from './doctype'
import type { ErrorItems } from './error-items'
import { IssuerSigned, type IssuerSignedStructure } from './issuer-signed'
import type { Namespace } from './namespace'

const schema = cborMap([
  ['docType', z.string()],
  ['issuerSigned', cborStructure(IssuerSigned)],
  ['deviceSigned', cborStructure(DeviceSigned)],
  ['errors', z.map(z.string(), z.unknown()).optional()],
])

export type DocumentStructure = {
  docType: DocType
  issuerSigned: IssuerSignedStructure
  deviceSigned: DeviceSignedStructure
  errors?: Map<Namespace, ErrorItems>
}

export type DocumentOptions = {
  docType: DocType
  issuerSigned: IssuerSigned
  deviceSigned: DeviceSigned
  errors?: Map<Namespace, ErrorItems>
}

export class Document extends CborStructure {
  public static override schema = schema

  public constructor(options: DocumentOptions) {
    super(
      buildStructure([
        ['docType', options.docType],
        ['issuerSigned', options.issuerSigned],
        ['deviceSigned', options.deviceSigned],
        ['errors', options.errors],
      ])
    )
  }

  public get docType(): DocType {
    return this.structure.get('docType') as DocType
  }

  public get issuerSigned(): IssuerSigned {
    return this.structure.get('issuerSigned') as IssuerSigned
  }

  public get deviceSigned(): DeviceSigned {
    return this.structure.get('deviceSigned') as DeviceSigned
  }

  public get errors(): Map<Namespace, ErrorItems> | undefined {
    return this.structure.get('errors') as Map<Namespace, ErrorItems> | undefined
  }

  public getIssuerNamespace(namespace: Namespace) {
    return this.issuerSigned.issuerNamespaces?.issuerNamespaces.get(namespace)
  }

  public override encodedStructure(): DocumentStructure {
    return super.encodedStructure() as DocumentStructure
  }

  public static override fromEncodedStructure(encodedStructure: unknown): Document {
    return fromEncoded(Document, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): Document {
    return decodeBytes(Document, bytes, options)
  }
}
