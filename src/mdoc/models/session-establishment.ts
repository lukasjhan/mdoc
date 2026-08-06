import { z } from 'zod'
import { buildStructure, CborStructure, cborDataItem, cborMap, type DataItem } from '../../cbor'
import type { MdocContext } from '../../context'
import type { CoseKey } from '../../cose'
import { EReaderKey, type EReaderKeyStructure } from './e-reader-key'
import type { SessionTranscript } from './session-transcript'

const schema = cborMap([
  ['eReaderKey', cborDataItem(EReaderKey)],
  ['data', z.instanceof(Uint8Array)],
])

export type SessionEstablishmentStructure = {
  eReaderKey: DataItem<EReaderKeyStructure>
  data: Uint8Array
}

export type SessionEstablishmentOptions = {
  eReaderKey: EReaderKey
  data: Uint8Array
}

export class SessionEstablishment extends CborStructure {
  public static override schema = schema

  public constructor(options: SessionEstablishmentOptions) {
    super(
      buildStructure([
        ['eReaderKey', options.eReaderKey],
        ['data', options.data],
      ])
    )
  }

  public get eReaderKey(): EReaderKey {
    return this.structure.get('eReaderKey') as EReaderKey
  }

  public get data(): Uint8Array {
    return this.structure.get('data') as Uint8Array
  }

  public async decryptedData(
    options: {
      eDeviceKeyPrivate: CoseKey
      eReaderKeyPublic: CoseKey
      sessionTranscript: SessionTranscript
    },
    ctx: Pick<MdocContext, 'crypto'>
  ) {
    const _key = await ctx.crypto.calculateEphemeralMacKey({
      privateKey: options.eDeviceKeyPrivate.privateKey,
      publicKey: options.eReaderKeyPublic.publicKey,
      sessionTranscriptBytes: options.sessionTranscript.encode({ asDataItem: true }),
      info: 'SKReader',
    })

    // TODO: we need to add a ctx.crypto.decrypt method
    throw new Error('unimplemented: ctx.crypto.decrypt must be added')
  }

  public override encodedStructure(): SessionEstablishmentStructure {
    return super.encodedStructure() as SessionEstablishmentStructure
  }
}
