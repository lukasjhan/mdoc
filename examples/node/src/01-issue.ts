/**
 * Issuing an mDL.
 *
 * An issuer takes a set of claims, hashes each one under its own random salt,
 * and signs the digests -- not the values -- into a Mobile Security Object.
 * That indirection is what lets the holder disclose a subset later without
 * breaking the signature.
 *
 *   pnpm issue
 */

import { DateOnly, Issuer, SignatureAlgorithm } from '@m-doc/core'
import { buildAgeAttestations, findMissingMandatoryElements, MDL_DOC_TYPE, MDL_NAMESPACE } from '@m-doc/mdl'
import { createCertificate, ctx, field, generateKeyPair, heading, run, truncate } from './shared'

const main = async () => {
  const issuer = await generateKeyPair()
  const device = await generateKeyPair()
  const certificate = await createCertificate({ keys: issuer.keys })

  // The MSO says when the document is valid. 7.2.5 wants the age attestations
  // evaluated at validFrom rather than at the moment of signing.
  const signed = new Date()
  const validFrom = signed
  const validUntil = new Date(Date.now() + 10 * 365 * 86_400_000)

  const claims = {
    family_name: 'Doe',
    given_name: 'Jane',
    // A full-date is CBOR tag 1004 -- neither a string nor a tdate
    birth_date: new DateOnly('1990-04-12'),
    issue_date: new DateOnly('2024-01-01'),
    expiry_date: new DateOnly('2034-01-01'),
    issuing_country: 'NL',
    issuing_authority: 'RDW',
    document_number: 'NL-2024-000123',
    un_distinguishing_sign: 'NL',
    // An array of CBOR maps; @m-doc/mdl reads it back into something typed
    driving_privileges: [
      new Map<string, unknown>([
        ['vehicle_category_code', 'B'],
        ['issue_date', new DateOnly('2024-01-01')],
        ['expiry_date', new DateOnly('2034-01-01')],
      ]),
    ],
    // A portrait is a byte string; a stand-in here
    portrait: new Uint8Array([0xff, 0xd8, 0xff, 0xe0]),

    // age_over_NN, computed rather than hand-written
    ...buildAgeAttestations('1990-04-12', validFrom, [18, 21, 65]),
  }

  heading('Claims')
  for (const [name, value] of Object.entries(claims)) {
    field(name, value instanceof Uint8Array ? `<${value.length} bytes>` : value)
  }

  // @m-doc/mdl knows Table 5; a document meant to be complete carries all of it
  const missing = findMissingMandatoryElements(claims)
  field('missing mandatory', missing.length === 0 ? 'none' : missing.join(', '))

  const issuerSigned = await new Issuer(MDL_DOC_TYPE, ctx).addIssuerNamespace(MDL_NAMESPACE, claims).sign({
    signingKey: issuer.privateKey,
    certificate,
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    // Binds the document to a key the holder controls, so only that holder can present it
    deviceKeyInfo: { deviceKey: device.publicKey },
    validityInfo: { signed, validFrom, validUntil },

    // Optional: where to look the document up for revocation
    status: { statusList: { idx: 412, uri: 'https://issuer.example.com/statuslists/1' } },
  })

  const mso = issuerSigned.issuerAuth.mobileSecurityObject

  heading('Mobile Security Object')
  field('version', mso.version)
  field('docType', mso.docType)
  field('digestAlgorithm', mso.digestAlgorithm)
  field('digests', mso.valueDigests.valueDigests.get(MDL_NAMESPACE)?.size)
  field('validFrom', mso.validityInfo.validFrom.toISOString())
  field('validUntil', mso.validityInfo.validUntil.toISOString())
  field('status', mso.status ? 'status list entry present' : 'none')

  heading('IssuerSigned')
  field('bytes', issuerSigned.encode().length)
  // The encoding OpenID4VCI hands to a wallet
  field('base64url', truncate(issuerSigned.encodedForOid4Vci))

  heading('What the wallet reads back')
  for (const [name, value] of Object.entries(issuerSigned.getAllPrettyClaims()[MDL_NAMESPACE])) {
    field(name, value instanceof Uint8Array ? `<${value.length} bytes>` : value)
  }

  // Or as JSON: bytes become base64url, a DateOnly becomes '1990-04-12'
  heading('The same claims as JSON')
  console.log(JSON.stringify(issuerSigned.getAllPrettyClaimsAsJson()[MDL_NAMESPACE], null, 2))
}

run(main)
