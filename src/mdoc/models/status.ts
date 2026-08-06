import { type CborDecodeOptions, CborStructure, cborDecode } from '../../cbor'

/**
 * `StatusListInfo` — a reference into an IETF Token Status List (`draft-ietf-oauth-status-list`).
 * `idx` is the credential's index in the packed status array; `uri` locates the `statuslist+jwt`.
 * Encoded as a CBOR map with the tstr keys `idx` (uint) and `uri` (tstr).
 */
export type StatusListInfoStructure = {
  idx: number
  uri: string
}

export type StatusListInfoOptions = {
  idx: number
  uri: string
}

export class StatusListInfo extends CborStructure {
  public idx: number
  public uri: string

  public constructor(options: StatusListInfoOptions) {
    super()
    this.idx = options.idx
    this.uri = options.uri
  }

  public encodedStructure(): StatusListInfoStructure {
    return {
      idx: this.idx,
      uri: this.uri,
    }
  }

  public static override fromEncodedStructure(
    encodedStructure: StatusListInfoStructure | Map<string, unknown>
  ): StatusListInfo {
    let structure = encodedStructure as StatusListInfoStructure

    if (encodedStructure instanceof Map) {
      structure = Object.fromEntries(encodedStructure.entries()) as StatusListInfoStructure
    }

    return new StatusListInfo({ idx: structure.idx, uri: structure.uri })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): StatusListInfo {
    const structure = cborDecode<StatusListInfoStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })

    return StatusListInfo.fromEncodedStructure(structure)
  }
}

/**
 * `Status` — the optional `status` element of the MobileSecurityObject (ISO/IEC 18013-5:2021 2nd edition).
 * It carries the credential's revocation reference. Only `status_list` is modelled here (the mechanism
 * mandated by HAIP / ETSI TS 119 472-3 for EUDI); unknown entries are preserved on decode so an
 * `identifier_list` (or any future member) survives a round-trip.
 */
export type StatusStructure = {
  status_list?: StatusListInfoStructure
} & Record<string, unknown>

export type StatusOptions = {
  statusList?: StatusListInfo | StatusListInfoOptions
}

export class Status extends CborStructure {
  public statusList?: StatusListInfo
  /** Any non-`status_list` members, preserved verbatim across a decode/encode round-trip. */
  public additional: Map<string, unknown>

  public constructor(options: StatusOptions & { additional?: Map<string, unknown> }) {
    super()
    this.statusList = options.statusList
      ? options.statusList instanceof StatusListInfo
        ? options.statusList
        : new StatusListInfo(options.statusList)
      : undefined
    this.additional = options.additional ?? new Map()
  }

  public encodedStructure(): StatusStructure {
    const structure: StatusStructure = {}

    if (this.statusList) {
      structure.status_list = this.statusList.encodedStructure()
    }

    for (const [key, value] of this.additional) {
      structure[key] = value
    }

    return structure
  }

  public static override fromEncodedStructure(encodedStructure: StatusStructure | Map<string, unknown>): Status {
    const entries =
      encodedStructure instanceof Map ? encodedStructure : new Map<string, unknown>(Object.entries(encodedStructure))

    const statusListEntry = entries.get('status_list')

    const additional = new Map<string, unknown>()
    for (const [key, value] of entries) {
      if (key !== 'status_list') additional.set(key, value)
    }

    return new Status({
      statusList: statusListEntry
        ? StatusListInfo.fromEncodedStructure(statusListEntry as StatusListInfoStructure | Map<string, unknown>)
        : undefined,
      additional,
    })
  }

  public static override decode(bytes: Uint8Array, options?: CborDecodeOptions): Status {
    const structure = cborDecode<StatusStructure>(bytes, { ...(options ?? {}), mapsAsObjects: false })

    return Status.fromEncodedStructure(structure)
  }
}
