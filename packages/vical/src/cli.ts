#!/usr/bin/env node

/**
 * Reads a VICAL from a file and prints what it holds.
 *
 * The signature is checked against `nodeVerificationContext`, so reading a
 * trust list costs no dependencies beyond what the library already has.
 */

import { readFileSync } from 'node:fs'
import { base64, base64url, hex } from '@m-doc/core'
import type { CertificateInfo } from './certificate-info'
import { nodeVerificationContext } from './node-verification'
import { SignedVical } from './signed-vical'
import { MDL_DOCTYPE, type Vical } from './vical'

type Options = {
  file: string
  json: boolean
  verbose: boolean
  verify: boolean
  pem: boolean
}

const HELP = `
Read an ISO/IEC 18013-5 Annex C VICAL and print what it holds.

Usage:
  vical [options] <file>
  vical [options] -            read from stdin

Options:
  -j, --json       print JSON instead of a table
  -v, --verbose    add sizes, doc types and the full country list
      --pem        print each certificate as PEM, and nothing else
      --no-verify  skip the signature check
  -h, --help       print this
      --version    print the version

The file may hold raw CBOR, or hex, base64 or base64url text.

Exit codes:
  0  read, and the signature verified
  1  could not be read
  2  read, but the signature did not verify
`

const parseArgs = (argv: Array<string>): Options => {
  const options: Options = { file: '', json: false, verbose: false, verify: true, pem: false }

  for (const arg of argv) {
    if (arg === '--json' || arg === '-j') options.json = true
    else if (arg === '--verbose' || arg === '-v') options.verbose = true
    else if (arg === '--pem') options.pem = true
    else if (arg === '--no-verify') options.verify = false
    else if (arg === '--help' || arg === '-h') {
      process.stdout.write(HELP)
      process.exit(0)
    } else if (arg === '--version') {
      process.stdout.write(`${VERSION}\n`)
      process.exit(0)
    } else if (arg.startsWith('-') && arg !== '-') {
      fail(`Unknown option: ${arg}. Try --help.`)
    } else if (options.file) {
      fail(`Expected one file, got "${options.file}" and "${arg}".`)
    } else {
      options.file = arg
    }
  }

  if (!options.file) fail('No input file. Try --help.')

  return options
}

/** The bundler inlines package.json, so this is the version that was built. */
const VERSION = (() => {
  try {
    return (require('../package.json') as { version: string }).version
  } catch {
    return 'unknown'
  }
})()

function fail(message: string): never {
  process.stderr.write(`${message}\n`)
  process.exit(1)
}

const readStdin = (): Uint8Array => {
  try {
    return new Uint8Array(readFileSync(0))
  } catch {
    fail('Could not read stdin.')
  }
}

/** Raw CBOR, or text holding one of the encodings people paste around. */
const readInput = (file: string): Uint8Array => {
  let bytes: Uint8Array

  if (file === '-') {
    bytes = readStdin()
  } else {
    try {
      bytes = new Uint8Array(readFileSync(file))
    } catch (error) {
      fail(`Could not read ${file}: ${(error as Error).message}`)
    }
  }

  if (bytes.length === 0) fail('The input is empty.')

  // A CBOR VICAL starts with a tag or an array; anything decodable as clean
  // ASCII is far more likely to be an encoding of one
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes).trim()
  } catch {
    return bytes
  }

  const compact = text.replace(/\s+/g, '')

  if (/^[0-9a-fA-F]+$/.test(compact) && compact.length % 2 === 0) return hex.decode(compact)
  if (/^[A-Za-z0-9_-]+$/.test(compact)) return base64url.decode(compact)
  if (/^[A-Za-z0-9+/]+=*$/.test(compact)) return base64.decode(compact)

  return bytes
}

const asJson = (vical: Vical, signed: SignedVical, verified: boolean | undefined, verbose: boolean) => {
  const certificate = (info: CertificateInfo) => {
    const entry: Record<string, unknown> = {
      issuingCountry: info.issuingCountry,
      issuingAuthority: info.issuingAuthority,
      serialNumber: info.serialNumber.toString(),
      ski: hex.encode(info.ski),
      docType: info.docType,
    }

    if (info.stateOrProvinceName) entry.stateOrProvinceName = info.stateOrProvinceName
    if (info.certificateProfile) entry.certificateProfile = info.certificateProfile
    if (info.notBefore) entry.notBefore = info.notBefore.toISOString()
    if (info.notAfter) entry.notAfter = info.notAfter.toISOString()
    if (verbose) entry.certificateSize = info.certificate.length

    return entry
  }

  const output: Record<string, unknown> = {
    version: vical.version,
    vicalProvider: vical.vicalProvider,
    date: vical.date.toISOString(),
    algorithm: signed.signatureAlgorithmName,
    certificateCount: vical.certificateInfos.length,
  }

  if (vical.vicalIssueID !== undefined) output.vicalIssueID = vical.vicalIssueID
  if (vical.nextUpdate) output.nextUpdate = vical.nextUpdate.toISOString()
  if (verified !== undefined) output.signatureValid = verified

  output.certificates = vical.certificateInfos.map(certificate)

  if (verbose) {
    output.signatureSize = signed.signature?.length
    output.certificateChainLength = signed.certificateChain.length
    output.mdlCertificateCount = vical.forDocType(MDL_DOCTYPE).length
    output.supportedCountries = [...vical.trustAnchors().keys()].sort()
  }

  return output
}

const printTable = (vical: Vical, signed: SignedVical, verified: boolean | undefined, verbose: boolean) => {
  const line = (char: string) => process.stdout.write(`${char.repeat(64)}\n`)
  const field = (label: string, value: unknown) => process.stdout.write(`${`${label}:`.padEnd(17)}${value}\n`)

  line('=')
  process.stdout.write('VICAL\n')
  line('=')

  field('Provider', vical.vicalProvider)
  field('Version', vical.version)
  field('Date', vical.date.toISOString())
  if (vical.vicalIssueID !== undefined) field('Issue ID', vical.vicalIssueID)
  if (vical.nextUpdate) field('Next update', vical.nextUpdate.toISOString())
  field('Algorithm', signed.signatureAlgorithmName)
  field('Certificates', vical.certificateInfos.length)

  if (verified !== undefined) field('Signature', verified ? 'valid' : 'INVALID')
  if (vical.nextUpdate && vical.nextUpdate < new Date()) field('Staleness', 'past nextUpdate')

  if (verbose) {
    field('Signature size', `${signed.signature?.length ?? 0} bytes`)
    field('x5chain', `${signed.certificateChain.length} certificates`)
  }

  process.stdout.write('\n')
  line('-')
  process.stdout.write('Certificates\n')
  line('-')

  vical.certificateInfos.forEach((info, index) => {
    process.stdout.write(`\n[${index + 1}] ${info.issuingCountry ?? '??'} - ${info.issuingAuthority ?? 'unnamed'}\n`)
    process.stdout.write(`    Serial:    ${info.serialNumber}\n`)
    process.stdout.write(`    SKI:       ${hex.encode(info.ski)}\n`)
    process.stdout.write(`    Doc types: ${info.docType.join(', ')}\n`)

    if (info.stateOrProvinceName) process.stdout.write(`    State:     ${info.stateOrProvinceName}\n`)
    if (info.certificateProfile) process.stdout.write(`    Profile:   ${info.certificateProfile.join(', ')}\n`)
    if (info.notBefore && info.notAfter) {
      process.stdout.write(
        `    Validity:  ${info.notBefore.toISOString().slice(0, 10)} to ${info.notAfter.toISOString().slice(0, 10)}\n`
      )
    }
    if (verbose) process.stdout.write(`    Size:      ${info.certificate.length} bytes\n`)
  })

  process.stdout.write('\n')
  line('-')
  process.stdout.write('mDL trust anchors\n')
  line('-')

  const anchors = [...vical.trustAnchors().keys()].sort()
  field('Countries', anchors.length)
  process.stdout.write(`${anchors.join(', ')}\n`)
}

const main = async () => {
  const options = parseArgs(process.argv.slice(2))
  const bytes = readInput(options.file)

  let signed: SignedVical
  try {
    signed = SignedVical.decode(bytes)
  } catch (error) {
    fail(`Not a VICAL: ${(error as Error).message}`)
  }

  let vical: Vical
  try {
    vical = signed.vical
  } catch (error) {
    fail(`Could not read the list: ${(error as Error).message}`)
  }

  if (options.pem) {
    for (const info of vical.certificateInfos) process.stdout.write(info.toPem())
    return
  }

  let verified: boolean | undefined
  if (options.verify) {
    try {
      verified = await signed.verify({}, nodeVerificationContext)
    } catch (error) {
      process.stderr.write(`Could not check the signature: ${(error as Error).message}\n`)
      verified = false
    }
  }

  if (options.json) {
    process.stdout.write(`${JSON.stringify(asJson(vical, signed, verified, options.verbose), null, 2)}\n`)
  } else {
    printTable(vical, signed, verified, options.verbose)
  }

  if (verified === false) process.exit(2)
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`)
  process.exit(1)
})
