/**
 * Verifying a response.
 *
 * Verification is a series of named checks in five categories, each reported to
 * a callback. The default callback throws on the first failure; passing your
 * own collects every check instead, which is what a diagnostic tool wants and
 * what this example shows.
 *
 *   pnpm verify
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
  type VerificationAssessment,
  Verifier,
} from '@m-doc/core'
import { isExpired, isNotYetValid, MDL_DOC_TYPE, MDL_NAMESPACE } from '@m-doc/mdl'
import { createCertificate, ctx, field, generateKeyPair, heading, run } from './shared'

const main = async () => {
  const issuer = await generateKeyPair()
  const device = await generateKeyPair()
  const certificate = await createCertificate({ keys: issuer.keys })

  const now = new Date()
  const issuerSigned = await new Issuer(MDL_DOC_TYPE, ctx)
    .addIssuerNamespace(MDL_NAMESPACE, {
      family_name: 'Doe',
      given_name: 'Jane',
      birth_date: new DateOnly('1990-04-12'),
      issue_date: new DateOnly('2024-01-01'),
      expiry_date: new DateOnly('2034-01-01'),
      // The issuer's own certificate says C=NL; a mismatch here is a failed check
      issuing_country: 'NL',
      issuing_authority: 'RDW',
      document_number: 'NL-2024-000123',
      age_over_18: true,
    })
    .sign({
      signingKey: issuer.privateKey,
      certificate,
      algorithm: SignatureAlgorithm.ES256,
      digestAlgorithm: 'SHA-256',
      deviceKeyInfo: { deviceKey: device.publicKey },
      validityInfo: { signed: now, validFrom: now, validUntil: new Date(Date.now() + 10 * 365 * 86_400_000) },
    })

  const sessionTranscript = await SessionTranscript.forOid4Vp(
    {
      clientId: 'x509_san_dns:verifier.example.com',
      responseUri: 'https://verifier.example.com/response',
      nonce: 'n-0S6_WzA2Mj',
    },
    ctx
  )

  const deviceRequest = new DeviceRequest({
    docRequests: [
      new DocRequest({
        itemsRequest: new ItemsRequest({
          docType: MDL_DOC_TYPE,
          namespaces: { [MDL_NAMESPACE]: { family_name: false, issuing_country: false, age_over_18: false } },
        }),
      }),
    ],
  })

  const presented = await Holder.createDeviceResponseForDeviceRequest(
    { deviceRequest, sessionTranscript, issuerSigned: [issuerSigned], signature: { signingKey: device.privateKey } },
    ctx
  )

  // What the verifier actually receives: bytes, not an object
  const deviceResponse = DeviceResponse.decode(presented.encode())

  const checks: Array<VerificationAssessment> = []

  await Verifier.verifyDeviceResponse(
    {
      deviceResponse,
      sessionTranscript,
      // Anchors should be IACA roots. This example is self-signed, so the
      // document signer is its own anchor.
      trustedCertificates: [certificate],
      // Optional: also check the response answers what was asked
      deviceRequest,
      now,
      // Collect every check rather than throwing on the first failure
      onCheck: (item) => checks.push(item),
    },
    ctx
  )

  const categories = ['DOCUMENT_FORMAT', 'ISSUER_AUTH', 'DEVICE_AUTH', 'DATA_INTEGRITY', 'READER_AUTH'] as const

  for (const category of categories) {
    const inCategory = checks.filter((check) => check.category === category)
    if (inCategory.length === 0) continue

    heading(category)
    for (const check of inCategory) {
      const mark = check.status === 'PASSED' ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m'
      console.log(`  ${mark} ${check.check}`)
      if (check.reason) console.log(`    ${check.reason}`)
    }
  }

  const failed = checks.filter((check) => check.status === 'FAILED')

  heading('Result')
  field('checks run', checks.length)
  field('failed', failed.length)

  if (failed.length > 0) {
    // The default callback would have thrown MdlError here instead
    process.exitCode = 1
    return
  }

  const claims = deviceResponse.getAllPrettyClaims()[MDL_DOC_TYPE][MDL_NAMESPACE]

  heading('Trusted claims')
  for (const [name, value] of Object.entries(claims)) field(name, value)

  // Validity is a profile question, not a signature question: the document can
  // be perfectly signed and still be out of date.
  heading('Profile checks')
  field('expired', isExpired(claims) ?? 'expiry_date not disclosed')
  field('not yet valid', isNotYetValid(claims) ?? 'issue_date not disclosed')
}

run(main)
