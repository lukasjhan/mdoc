import { z } from 'zod'
import {
  buildStructure,
  type CborDecodeOptions,
  CborStructure,
  cborArray,
  cborDataItem,
  cborDecode,
  type DataItem,
  decodeBytes,
  fromEncoded,
} from '../../cbor'
import { DeviceNamespaces, type DeviceNamespacesStructure } from './device-namespaces'
import type { DocType } from './doctype'
import { SessionTranscript, type SessionTranscriptStructure } from './session-transcript'

/**
 * A caller may present a session transcript this library does not model -- the
 * transcript is opaque to device authentication, which only ever hashes over
 * it. One that parses becomes a `SessionTranscript`; anything else is carried
 * through exactly as it arrived.
 */
const sessionTranscriptOrOpaque = z.codec(z.unknown(), z.unknown(), {
  decode: (encoded) => {
    try {
      return SessionTranscript.fromEncodedStructure(encoded)
    } catch {
      return encoded
    }
  },
  encode: (value) => (value instanceof SessionTranscript ? value.encodedStructure() : value),
})

const schema = cborArray([
  ['context', z.literal('DeviceAuthentication')],
  ['sessionTranscript', sessionTranscriptOrOpaque],
  ['docType', z.string()],
  ['deviceNameSpaces', cborDataItem(DeviceNamespaces)],
])

export type DeviceAuthenticationStructure = [
  string,
  SessionTranscriptStructure,
  DocType,
  DataItem<DeviceNamespacesStructure>,
]

export type DeviceAuthenticationOptions = {
  sessionTranscript: SessionTranscript | Uint8Array
  docType: DocType
  deviceNamespaces: DeviceNamespaces
}

export class DeviceAuthentication extends CborStructure {
  public static override schema = schema

  public constructor(options: DeviceAuthenticationOptions) {
    super(
      buildStructure([
        ['context', 'DeviceAuthentication'],
        [
          'sessionTranscript',
          options.sessionTranscript instanceof SessionTranscript
            ? options.sessionTranscript
            : cborDecode(options.sessionTranscript),
        ],
        ['docType', options.docType],
        ['deviceNameSpaces', options.deviceNamespaces],
      ])
    )
  }

  /** Undefined when the transcript is one this library does not model. */
  public get sessionTranscript(): SessionTranscript | undefined {
    const value = this.structure.get('sessionTranscript')

    return value instanceof SessionTranscript ? value : undefined
  }

  public get docType(): DocType {
    return this.structure.get('docType') as DocType
  }

  public get deviceNamespaces(): DeviceNamespaces {
    return this.structure.get('deviceNameSpaces') as DeviceNamespaces
  }

  public override encodedStructure(): DeviceAuthenticationStructure {
    return super.encodedStructure() as DeviceAuthenticationStructure
  }

  public static override fromEncodedStructure(encodedStructure: unknown): DeviceAuthentication {
    return fromEncoded(DeviceAuthentication, encodedStructure)
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): DeviceAuthentication {
    return decodeBytes(DeviceAuthentication, bytes, options)
  }
}
