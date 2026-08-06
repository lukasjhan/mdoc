import { describe, expect, it } from 'vitest'
import { nodeVerificationContext } from '../src/node-verification'
import { SignedVical } from '../src/signed-vical'
import { signedVicalBytes } from './fixtures/vical'

/**
 * The CLI checks signatures with Node's own primitives rather than
 * `@m-doc/context`, so that reading a trust list costs no dependencies. If this
 * drifts from what `@m-doc/context` does, the CLI quietly starts trusting lists
 * it should not.
 */
describe('node verification context', () => {
  it('verifies a real signed VICAL', async () => {
    const signed = SignedVical.decode(signedVicalBytes)

    await expect(signed.verify({}, nodeVerificationContext)).resolves.toBe(true)
  })

  it('rejects a tampered signature', async () => {
    const tampered = Uint8Array.from(signedVicalBytes)
    tampered[tampered.length - 1] ^= 0xff

    const signed = SignedVical.decode(tampered)

    await expect(signed.verify({}, nodeVerificationContext)).resolves.toBe(false)
  })

  it('rejects a tampered payload', async () => {
    const payload = SignedVical.decode(signedVicalBytes).payload

    expect(payload).toBeTruthy()
    if (!payload) return

    // Locate the payload inside the envelope rather than guessing an offset,
    // then flip one byte of the list while leaving the signature alone
    const haystack = Buffer.from(signedVicalBytes)
    const offset = haystack.indexOf(Buffer.from(payload))

    expect(offset).toBeGreaterThan(-1)

    const tampered = Uint8Array.from(signedVicalBytes)
    tampered[offset + 40] ^= 0x01

    await expect(SignedVical.decode(tampered).verify({}, nodeVerificationContext)).resolves.toBe(false)
  })

  it('refuses the operations it does not implement', () => {
    expect(() => nodeVerificationContext.x509.verifyCertificateChain({ trustedCertificates: [], x5chain: [] })).toThrow(
      /verify-only/
    )
    expect(() => nodeVerificationContext.cose.mac0.verify({} as never)).toThrow(/verify-only/)
  })
})
