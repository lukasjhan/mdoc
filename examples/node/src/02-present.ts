/**
 * Presenting a document.
 *
 * A verifier asks for named elements; the wallet answers with those and no
 * others. The issuer's signature still verifies, because the MSO holds digests
 * rather than values -- the elements left behind simply have no matching
 * IssuerSignedItem in the response.
 *
 *   pnpm present
 */

import {
  DateOnly,
  DeviceRequest,
  DeviceResponse,
  DocRequest,
  Holder,
  Issuer,
  ItemsRequest,
  SessionTranscript,
  SignatureAlgorithm,
} from '@m-doc/core'
import { buildAgeAttestations, MDL_DOC_TYPE, MDL_NAMESPACE, resolveAgeAttestation } from '@m-doc/mdl'
import { createCertificate, ctx, field, generateKeyPair, heading, run, truncate } from './shared'

const main = async () => {
  const issuer = await generateKeyPair()
  const device = await generateKeyPair()
  const certificate = await createCertificate({ keys: issuer.keys })

  const now = new Date()
  const claims = {
    family_name: 'Doe',
    given_name: 'Jane',
    birth_date: new DateOnly('1990-04-12'),
    issue_date: new DateOnly('2024-01-01'),
    expiry_date: new DateOnly('2034-01-01'),
    issuing_country: 'NL',
    issuing_authority: 'RDW',
    document_number: 'NL-2024-000123',
    ...buildAgeAttestations('1990-04-12', now, [21]),
  }

  const issuerSigned = await new Issuer(MDL_DOC_TYPE, ctx).addIssuerNamespace(MDL_NAMESPACE, claims).sign({
    signingKey: issuer.privateKey,
    certificate,
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    deviceKeyInfo: { deviceKey: device.publicKey },
    validityInfo: { signed: now, validFrom: now, validUntil: new Date(Date.now() + 10 * 365 * 86_400_000) },
  })

  heading('In the wallet')
  field('docType', MDL_DOC_TYPE)
  field('elements', Object.keys(issuerSigned.getAllPrettyClaims()[MDL_NAMESPACE]).join(', '))

  /*
   * The session transcript binds the presentation to the exchange it happened
   * in -- so a response captured off the wire cannot be replayed elsewhere.
   * Which constructor to use is decided by the protocol, not by preference;
   * getting it wrong is the usual cause of a device signature that will not
   * verify. Here: OpenID4VP over a redirect.
   */
  const sessionTranscript = await SessionTranscript.forOid4Vp(
    {
      clientId: 'x509_san_dns:verifier.example.com',
      responseUri: 'https://verifier.example.com/response',
      nonce: 'n-0S6_WzA2Mj',
    },
    ctx
  )

  // The verifier asks for three elements. `false` is intentToRetain: the
  // verifier says whether it will keep the value beyond the transaction.
  const deviceRequest = new DeviceRequest({
    docRequests: [
      new DocRequest({
        itemsRequest: new ItemsRequest({
          docType: MDL_DOC_TYPE,
          namespaces: {
            [MDL_NAMESPACE]: { family_name: false, document_number: true, age_over_21: false },
          },
        }),
      }),
    ],
  })

  heading('Requested')
  for (const docRequest of deviceRequest.docRequests) {
    for (const [namespace, elements] of docRequest.itemsRequest.namespaces) {
      for (const [element, intentToRetain] of elements) {
        field(`${namespace}/${element}`, intentToRetain ? 'intentToRetain' : '')
      }
    }
  }

  const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
    {
      deviceRequest,
      sessionTranscript,
      issuerSigned: [issuerSigned],
      // The device key the MSO named. Use `mac` instead for proximity.
      signature: { signingKey: device.privateKey },
    },
    ctx
  )

  heading('DeviceResponse')
  field('version', deviceResponse.version)
  field('status', deviceResponse.status)
  field('documents', deviceResponse.documents?.length)
  field('bytes', deviceResponse.encode().length)
  field('base64url', truncate(deviceResponse.encodedForOid4Vp))

  const disclosed = deviceResponse.getAllPrettyClaims()[MDL_DOC_TYPE][MDL_NAMESPACE]

  heading('Disclosed')
  for (const [name, value] of Object.entries(disclosed)) field(name, value)

  heading('Withheld')
  const withheld = Object.keys(claims).filter((name) => !(name in disclosed))
  field('elements', withheld.join(', '))
  field('birth_date', disclosed.birth_date ?? 'never left the wallet')

  /*
   * A request for age_over_18 is not a request for the element of that name.
   * ISO/IEC 18013-5 7.2.5: answer with the nearest TRUE attestation at or
   * above the age, failing that the nearest FALSE one at or below it.
   */
  heading('Answering an age request from what the wallet holds')
  field(
    'has',
    Object.keys(claims)
      .filter((name) => name.startsWith('age_over'))
      .join(', ')
  )
  field('asked for 18', JSON.stringify(resolveAgeAttestation(claims, 18)))
  field('asked for 65', JSON.stringify(resolveAgeAttestation(claims, 65)) ?? 'undefined')

  // What travels over the wire, and what the verifier decodes on the far side
  const received = DeviceResponse.decode(deviceResponse.encode())
  heading('Round-trips')
  field('same bytes', String(received.encode().length === deviceResponse.encode().length))
}

run(main)
