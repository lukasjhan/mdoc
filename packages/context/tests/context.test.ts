import { CoseKey, Header, hex, ProtectedHeaders, Sign1, SignatureAlgorithm } from '@m-doc/core'
import { describe, expect, it } from 'vitest'
import { createMdocContext } from '../src'

const ctx = createMdocContext()

const jwk = {
  kty: 'EC',
  crv: 'P-256',
  d: 'hGc90b8KMIjIpZos81yEFbOMc0Ww3k5ZNWICzDwtFV4',
  x: 'eBUFGSPkdYwJ9TqYpcNxhAyr-A8wlWzrLQJppSi3x0E',
  y: 'Jnf8v4steg6Gr4IEFpg_xcM5xdHKdngbQN9ERJbJvl8',
  alg: 'ES256',
}

describe('crypto', () => {
  it('digests', async () => {
    const digest = await ctx.crypto.digest({ digestAlgorithm: 'SHA-256', bytes: new Uint8Array() })

    // SHA-256 of the empty string
    expect(hex.encode(digest)).toBe('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
  })

  it('returns random bytes of the requested length', () => {
    expect(ctx.crypto.random(32)).toHaveLength(32)
    expect(hex.encode(ctx.crypto.random(16))).not.toBe(hex.encode(ctx.crypto.random(16)))
  })

  it('derives an ephemeral MAC key both sides agree on', async () => {
    const a = CoseKey.fromJwk(jwk)
    const b = CoseKey.fromJwk({
      ...jwk,
      d: 'IE0p-o20T9g9pG_zUva54oU1JlBrTGPa2EXJCLpGd6w',
      x: 'ekxLaTjYRP397Q4oI9tcx6hkCD63KGRUmpd4_kqXt0k',
      y: 'pPmJ9A6qkBuxnJZalAU-ieRqLs4tbwC_GOAGpNb_KCQ',
    })

    const shared = (privateKey: CoseKey, publicKey: CoseKey) =>
      ctx.crypto.calculateEphemeralMacKey({
        privateKey: privateKey.privateKey,
        publicKey: publicKey.publicKey,
        sessionTranscriptBytes: new Uint8Array([1, 2, 3]),
        info: 'EMacKey',
      })

    const fromA = await shared(a, b)
    const fromB = await shared(b, a)

    expect(hex.encode(fromA.privateKey)).toBe(hex.encode(fromB.privateKey))
  })
})

describe('cose', () => {
  const build = () =>
    new Sign1({
      protectedHeaders: new ProtectedHeaders({
        protectedHeaders: new Map([[Header.Algorithm, SignatureAlgorithm.ES256]]),
      }),
      payload: new Uint8Array([1, 2, 3]),
    })

  it('signs and verifies a Sign1', async () => {
    const key = CoseKey.fromJwk(jwk)
    const signed = await build().sign({ signingKey: key }, ctx)

    expect(signed.signature).toBeDefined()
    await expect(signed.verifySignature({ key }, ctx)).resolves.toBe(true)
  })

  it('rejects a signature made over different content', async () => {
    const key = CoseKey.fromJwk(jwk)
    const signed = await build().sign({ signingKey: key }, ctx)
    const tampered = signed.withDetachedContent(new Uint8Array([9, 9, 9]))

    await expect(tampered.verifySignature({ key }, ctx)).resolves.toBe(false)
  })
})

describe('createMdocContext', () => {
  it('rejects a runtime with no WebCrypto', () => {
    expect(() => createMdocContext({ crypto: undefined as never })).not.toThrow()
    expect(() => createMdocContext({ crypto: {} as never })).toThrow(/WebCrypto/)
  })
})
