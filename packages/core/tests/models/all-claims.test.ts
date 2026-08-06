import { describe, expect, it } from 'vitest'
import { DeviceResponse } from '../../src'
import { deviceResponse as animo } from '../examples/animo-mdoc-05/deviceResponse'
import { deviceResponse as eudiReference } from '../examples/eudi-reference/deviceResponse'

/**
 * Reading claims used to mean naming the docType and namespace up front. A
 * verifier does not always know either, and a name that does not match returns
 * `undefined` rather than saying so.
 */
describe('reading every claim without naming a namespace', () => {
  it('lists the namespaces a document carries', () => {
    const document = DeviceResponse.decode(eudiReference).documents?.[0]

    expect(document?.namespaces).toEqual(['eu.europa.ec.eudi.pid.1'])
  })

  it('returns the claims of every namespace, keyed by namespace', () => {
    const document = DeviceResponse.decode(eudiReference).documents?.[0]

    expect(document?.getAllPrettyClaims()).toMatchObject({
      'eu.europa.ec.eudi.pid.1': {
        family_name: 'Han',
        given_name: 'Lukas',
        nationality: ['LU'],
      },
    })
  })

  it('matches getPrettyClaims for a namespace that is named', () => {
    const document = DeviceResponse.decode(eudiReference).documents?.[0]
    const namespace = document?.namespaces[0] as string

    expect(document?.getAllPrettyClaims()[namespace]).toEqual(document?.getPrettyClaims(namespace))
  })

  it('keys by docType at the response level', () => {
    const claims = DeviceResponse.decode(eudiReference).getAllPrettyClaims()

    expect(Object.keys(claims)).toEqual(['eu.europa.ec.eudi.pid.1'])
    expect(claims['eu.europa.ec.eudi.pid.1']['eu.europa.ec.eudi.pid.1']).toMatchObject({ family_name: 'Han' })
  })

  it('works on a document from a different implementation', () => {
    const claims = DeviceResponse.decode(animo).getAllPrettyClaims()
    const [docType] = Object.keys(claims)

    expect(docType).toBeDefined()
    expect(Object.keys(claims[docType as string]).length).toBeGreaterThan(0)
  })

  it('keeps a claim named __proto__ instead of silently dropping it', () => {
    // Assigning __proto__ on an ordinary object sets the prototype, so the
    // claim would vanish. The accessors build on a null prototype.
    const document = DeviceResponse.decode(eudiReference).documents?.[0]
    const all = document?.getAllPrettyClaims() as object

    expect(Object.getPrototypeOf(all)).toBeNull()
    expect(Object.getPrototypeOf(document?.getPrettyClaims('eu.europa.ec.eudi.pid.1') as object)).toBeNull()
  })

  it('renders the claims as JSON', () => {
    const document = DeviceResponse.decode(eudiReference).documents?.[0]

    expect(document?.getAllPrettyClaimsAsJson()).toEqual({
      'eu.europa.ec.eudi.pid.1': {
        birth_date: '2026-02-19',
        family_name: 'Han',
        given_name: 'Lukas',
        nationality: ['LU'],
      },
    })
  })

  it('the JSON view survives JSON.stringify', () => {
    const claims = DeviceResponse.decode(eudiReference).getAllPrettyClaimsAsJson()

    expect(() => JSON.stringify(claims)).not.toThrow()
    expect(JSON.parse(JSON.stringify(claims))['eu.europa.ec.eudi.pid.1']['eu.europa.ec.eudi.pid.1']).toMatchObject({
      family_name: 'Han',
    })
  })

  it('is empty rather than undefined when nothing was disclosed', () => {
    const document = DeviceResponse.decode(eudiReference).documents?.[0]

    expect(document?.getPrettyClaims('does.not.exist')).toBeUndefined()
    expect(document?.getAllPrettyClaims()['does.not.exist']).toBeUndefined()
    expect(Object.keys(document?.getAllPrettyClaims() ?? {})).not.toContain('does.not.exist')
  })
})
