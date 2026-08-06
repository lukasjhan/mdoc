import { z } from 'zod'
import { buildStructure, type CborKey, CborStructure, cborMap, cborStructure } from '../../cbor'

/**
 * `StatusListInfo` -- a reference into an IETF Token Status List
 * (`draft-ietf-oauth-status-list`). `idx` is the credential's index in the
 * packed status array; `uri` locates the `statuslist+jwt`.
 */
const statusListInfoSchema = cborMap([
  ['idx', z.number()],
  ['uri', z.string()],
])

export type StatusListInfoStructure = {
  idx: number
  uri: string
}

export type StatusListInfoOptions = {
  idx: number
  uri: string
}

export class StatusListInfo extends CborStructure {
  public static override schema = statusListInfoSchema

  public constructor(options: StatusListInfoOptions) {
    super(
      buildStructure([
        ['idx', options.idx],
        ['uri', options.uri],
      ])
    )
  }

  public get idx(): number {
    return this.structure.get('idx') as number
  }

  public get uri(): string {
    return this.structure.get('uri') as string
  }

  public override encodedStructure(): StatusListInfoStructure {
    return super.encodedStructure() as StatusListInfoStructure
  }
}

/**
 * `Status` -- the optional `status` element of the MobileSecurityObject
 * (ISO/IEC 18013-5 second edition). It carries the credential's revocation
 * reference. Only `status_list` is modelled here, the mechanism HAIP and ETSI
 * TS 119 472-3 mandate for EUDI; any other member -- an `identifier_list`, or
 * anything added later -- is carried through untouched by the schema.
 */
const statusSchema = cborMap([['status_list', cborStructure(StatusListInfo).optional()]])

export type StatusStructure = {
  status_list?: StatusListInfoStructure
} & Record<string, unknown>

export type StatusOptions = {
  statusList?: StatusListInfo | StatusListInfoOptions
}

export class Status extends CborStructure {
  public static override schema = statusSchema

  public constructor(options: StatusOptions & { additional?: Map<string, unknown> }) {
    const statusList = options.statusList
      ? options.statusList instanceof StatusListInfo
        ? options.statusList
        : new StatusListInfo(options.statusList)
      : undefined

    super(buildStructure([['status_list', statusList], ...(options.additional ?? new Map<CborKey, unknown>())]))
  }

  public get statusList(): StatusListInfo | undefined {
    return this.structure.get('status_list') as StatusListInfo | undefined
  }

  /** Any non-`status_list` member, preserved verbatim across a round-trip. */
  public get additional(): Map<string, unknown> {
    const additional = new Map<string, unknown>()

    for (const [key, value] of this.structure) {
      if (key !== 'status_list') additional.set(String(key), value)
    }

    return additional
  }

  public override encodedStructure(): StatusStructure {
    return super.encodedStructure() as StatusStructure
  }
}
