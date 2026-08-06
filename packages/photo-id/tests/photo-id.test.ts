import { describe, expect, it } from 'vitest'
import {
  encodingFor,
  findMissingMandatoryElements,
  findTravelDocumentIssues,
  jurisdictionNamespace,
  PHOTO_ID_BASE_NAMESPACE,
  PHOTO_ID_DATAGROUPS_NAMESPACE,
  PHOTO_ID_DOC_TYPE,
  PHOTO_ID_MANDATORY_ELEMENTS,
  PHOTO_ID_NAMESPACE,
  PHOTO_ID_OPTIONAL_ELEMENTS,
  PHOTO_ID_SPECIFIC_ELEMENTS,
} from '../src'

describe('identifiers', () => {
  it('names the docType and the three namespaces', () => {
    expect(PHOTO_ID_DOC_TYPE).toBe('org.iso.23220.photoid.1')
    expect(PHOTO_ID_BASE_NAMESPACE).toBe('org.iso.23220.1')
    expect(PHOTO_ID_NAMESPACE).toBe('org.iso.23220.photoid.1')
    expect(PHOTO_ID_DATAGROUPS_NAMESPACE).toBe('org.iso.23220.datagroups.1')
  })

  it('builds a jurisdiction namespace', () => {
    // The example ISO/IEC TS 23220-4 gives for Iowa
    expect(jurisdictionNamespace('US-IA')).toBe('org.iso.23220.photoid.US-IA.1')
  })
})

describe('findMissingMandatoryElements', () => {
  const complete = {
    family_name: 'Han',
    given_name: 'Lukas',
    birth_date: '2000-01-01',
    portrait: new Uint8Array([1]),
    issue_date: '2020-01-01',
    expiry_date: '2030-01-01',
    issuing_authority: 'IND',
    issuing_country: 'NL',
    age_over_18: true,
  }

  it('reports nothing missing on a complete document', () => {
    expect(findMissingMandatoryElements(complete)).toEqual([])
  })

  it('names what is absent', () => {
    const missing = findMissingMandatoryElements({ family_name: 'Han' })

    expect(missing).toContain('portrait')
    expect(missing).toContain('age_over_18')
    expect(missing).not.toContain('family_name')
  })
})

describe('findTravelDocumentIssues', () => {
  /**
   * Table C.2 makes travel_document_type and travel_document_mrz conditional:
   * required where dg1 is present, optional otherwise.
   */
  it('requires the travel document elements once dg1 is present', () => {
    const issues = findTravelDocumentIssues({
      photoIdClaims: {},
      dataGroupClaims: { dg1: new Uint8Array([1]) },
    })

    expect(issues.map((issue) => issue.element)).toEqual(['travel_document_type', 'travel_document_mrz'])
  })

  it('is satisfied once both are there', () => {
    const issues = findTravelDocumentIssues({
      photoIdClaims: { travel_document_type: 'P', travel_document_mrz: 'P<NLDHAN<<LUKAS' },
      dataGroupClaims: { dg1: new Uint8Array([1]) },
    })

    expect(issues).toEqual([])
  })

  it('asks for nothing without dg1', () => {
    expect(findTravelDocumentIssues({ photoIdClaims: {} })).toEqual([])
    expect(findTravelDocumentIssues({ photoIdClaims: {}, dataGroupClaims: {} })).toEqual([])
  })
})

describe('element encodings', () => {
  it('gives the encoding the tables list', () => {
    expect(encodingFor('family_name')).toBe('tstr')
    expect(encodingFor('birth_date')).toBe('full-date')
    expect(encodingFor('portrait')).toBe('bstr')
    expect(encodingFor('sex')).toBe('uint')
    expect(encodingFor('age_over_18')).toBe('bool')
    expect(encodingFor('travel_document_mrz')).toBe('tstr')
  })

  it('covers every element the profile names', () => {
    for (const element of [
      ...PHOTO_ID_MANDATORY_ELEMENTS,
      ...PHOTO_ID_OPTIONAL_ELEMENTS,
      ...PHOTO_ID_SPECIFIC_ELEMENTS,
    ]) {
      expect(encodingFor(element), element).toBeDefined()
    }
  })

  it('has nothing to say about an element it does not name', () => {
    expect(encodingFor('org.example.custom')).toBeUndefined()
  })
})
