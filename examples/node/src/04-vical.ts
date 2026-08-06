/**
 * Reading a VICAL.
 *
 * A VICAL -- Verified Issuer Certificate Authority List, ISO/IEC 18013-5
 * Annex C -- is how a verifier learns which issuers to trust: a COSE_Sign1 over
 * a list of IACA certificates, published by a VICAL provider.
 *
 * This runs against a real one: AAMVA's list of US jurisdiction IACAs, fetched
 * on 2026-08-05 and committed as a fixture.
 *
 *   pnpm vical
 */

import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { hex } from '@m-doc/core'
import { MDL_DOCTYPE, SignedVical } from '@m-doc/vical'
import { ctx, field, heading, run } from './shared'

const main = async () => {
  const bytes = new Uint8Array(readFileSync(join(__dirname, '..', 'fixtures', 'aamva-vical.cbor')))

  const signed = SignedVical.decode(bytes)

  /*
   * The signature is what makes the list worth anything. With no key, the
   * public key is taken from the leaf of the x5chain -- which establishes only
   * that the list is internally consistent. To learn that it is the list you
   * meant to fetch, pass the provider's known key, or validate the chain
   * against a trust anchor of your own.
   */
  const isValid = await signed.verify({}, ctx)

  heading('Signature')
  field('algorithm', signed.signatureAlgorithmName)
  field('x5chain', `${signed.certificateChain.length} certificates`)
  field('self-consistent', isValid)

  if (!isValid) {
    console.error('VICAL signature did not verify')
    process.exitCode = 1
    return
  }

  const vical = signed.vical

  heading('VICAL')
  field('provider', vical.vicalProvider)
  field('version', vical.version)
  field('date', vical.date.toISOString())
  field('nextUpdate', vical.nextUpdate?.toISOString() ?? 'not given')
  field('issue ID', vical.vicalIssueID ?? 'not given')
  field('entries', vical.certificateInfos.length)

  // A list past its nextUpdate is stale, however valid its signature
  if (vical.nextUpdate && vical.nextUpdate < new Date()) {
    field('staleness', 'past nextUpdate — fetch a fresh list')
  }

  heading('Entries')
  for (const info of vical.forDocType(MDL_DOCTYPE).slice(0, 5)) {
    console.log(`  ${info.stateOrProvinceName ?? info.issuingCountry ?? '??'}  ${info.issuingAuthority ?? 'unnamed'}`)
    console.log(`     ski ${hex.encode(info.ski)}`)
    console.log(`     serial ${info.serialNumber}  valid to ${info.notAfter?.toISOString().slice(0, 10) ?? '—'}`)
  }
  console.log(`  … ${Math.max(0, vical.forDocType(MDL_DOCTYPE).length - 5)} more`)

  heading('Lookups')
  // By country. AAMVA lists US jurisdictions, so the subdivision is in
  // stateOrProvinceName rather than issuingCountry.
  field('forCountry("US")', vical.forCountry('US')?.issuingAuthority ?? 'none')

  // By Subject Key Identifier — how you go from an mDL's issuer certificate to
  // the trust anchor that vouches for it
  const someSki = vical.certificateInfos[0].ski
  field('forSubjectKeyIdentifier', vical.forSubjectKeyIdentifier(someSki)?.issuingAuthority ?? 'none')

  // By docType: an entry is listed for the document types it may issue
  field('forDocType(mDL)', `${vical.forDocType(MDL_DOCTYPE).length} entries`)
  field('forDocType(PhotoID)', `${vical.forDocType('org.iso.23220.photoid.1').length} entries`)

  heading('Feeding a verifier')
  const trustedCertificates = vical.certificates(MDL_DOCTYPE)
  field('trustedCertificates', `${trustedCertificates.length} DER certificates`)
  console.log(`
  await Verifier.verifyDeviceResponse(
    { deviceResponse, sessionTranscript, trustedCertificates: vical.certificates() },
    ctx
  )`)

  heading('One entry as PEM')
  console.log(
    vical.certificateInfos[0]
      .toPem()
      .split('\n')
      .slice(0, 4)
      .map((line) => `  ${line}`)
      .join('\n')
  )
  console.log('  …')

  // Members the spec reserves for future use survive decoding untouched, so a
  // list from a newer provider re-encodes to the bytes it arrived as
  heading('Round-trips')
  field('same bytes', hex.encode(signed.encode()) === hex.encode(bytes))
}

run(main)
