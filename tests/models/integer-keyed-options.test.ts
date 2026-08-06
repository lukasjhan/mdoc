import { describe, expect, it } from 'vitest'
import { hex } from '../../src'
import { BleOptions } from '../../src/mdoc/models/ble-options'
import { NfcOptions } from '../../src/mdoc/models/nfc-options'
import { WifiOptions } from '../../src/mdoc/models/wifi-options'

/**
 * The retrieval-option maps in ISO 18013-5 are keyed by unsigned integer. The
 * hand-written encoders built plain JavaScript objects, whose keys CBOR writes
 * as text strings -- `a2 6130 ...` where the wire calls for `a2 00 ...`. The
 * decoders read integer keys, so this library could not round-trip its own
 * output through a conformant peer.
 */
describe('retrieval options use integer keys on the wire', () => {
  it('NfcOptions', () => {
    const encoded = hex.encode(new NfcOptions({ maxLenCommandDataField: 255, maxLenResponseDataField: 256 }).encode())

    // a2 00 18ff 01 190100
    expect(encoded).toBe('a20018ff01190100')
    expect(encoded).not.toContain('6130')
  })

  it('BleOptions', () => {
    const encoded = hex.encode(new BleOptions({ peripheralServerMode: true, centralClientMode: false }).encode())

    // a2 00 f5 01 f4
    expect(encoded).toBe('a200f501f4')
  })

  it('WifiOptions omits every unset member', () => {
    expect(hex.encode(new WifiOptions({}).encode())).toBe('a0')
    // a1 00 61 "x"
    expect(hex.encode(new WifiOptions({ passPhrase: 'x' }).encode())).toBe('a1006178')
  })

  it('round-trips through decode', () => {
    const original = new BleOptions({
      peripheralServerMode: true,
      centralClientMode: true,
      centralClientModeUuid: new Uint8Array([1, 2, 3]),
    })

    const decoded = BleOptions.decode(original.encode())

    expect(decoded.peripheralServerMode).toBe(true)
    expect(decoded.centralClientMode).toBe(true)
    expect(decoded.centralClientModeUuid).toStrictEqual(new Uint8Array([1, 2, 3]))
    expect(decoded.peripheralServerModeUuid).toBeUndefined()
  })
})
