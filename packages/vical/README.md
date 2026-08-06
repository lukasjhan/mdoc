<h1 align="center"><b>@m-doc/vical</b></h1>

<p align="center">
  <a href="https://www.npmjs.com/package/@m-doc/vical">
    <img src="https://img.shields.io/npm/v/@m-doc/vical" />
  </a>
</p>

A VICAL — Verified Issuer Certificate Authority List — is the trust list an mDL
verifier checks issuer certificates against. ISO/IEC 18013-5:2021 Annex C
defines it as a CBOR list of IACA certificates, wrapped in a COSE_Sign1 signed
by the VICAL provider.

Part of [**m-doc**](https://github.com/lukasjhan/mdoc).
[`04-vical.ts`](https://github.com/lukasjhan/mdoc/blob/main/examples/node/src/04-vical.ts)
runs everything below against a real AAMVA list, or try it in the
[browser playground](https://mdoc-playground.vercel.app).

## CLI

Reading a trust list is often a one-off, so the package ships a command:

```bash
npx @m-doc/vical vical.cbor
```

```
================================================================
VICAL
================================================================
Provider:        AAMVA
Version:         1.0
Date:            2026-08-05T01:39:05.000Z
Issue ID:        344243
Next update:     2026-08-06T01:39:05.000Z
Algorithm:       ES256
Certificates:    20
Signature:       valid
Staleness:       past nextUpdate
...
```

The signature is checked by default, with Node's own primitives -- `node:crypto`
parses the signer certificate and WebCrypto checks the ECDSA -- so the command
needs nothing beyond this package.

| Option | |
| --- | --- |
| `-j`, `--json` | print JSON instead of a table |
| `-v`, `--verbose` | add sizes, chain length and the full country list |
| `--pem` | print each certificate as PEM, and nothing else |
| `--no-verify` | skip the signature check |
| `-h`, `--help` | usage |
| `--version` | the version that was built |

The input may be raw CBOR, or hex, base64 or base64url text. Pass `-` to read
stdin.

Exit codes make it scriptable: `0` read and verified, `1` could not be read,
`2` read but the signature did not verify.

```bash
# Trust anchors, straight out as PEM
npx @m-doc/vical --pem vical.cbor > anchors.pem

# Stop a pipeline on a list that does not verify
npx @m-doc/vical --json vical.cbor > vical.json || exit 1

# Which countries does this list cover?
npx @m-doc/vical --json -v vical.cbor | jq .supportedCountries
```

## Installation

```bash
npm i @m-doc/vical @m-doc/context
```

## Usage

```ts
import { createMdocContext } from '@m-doc/context'
import { SignedVical } from '@m-doc/vical'

const ctx = createMdocContext()
const signed = SignedVical.decode(bytes)

// The signature is what makes the list worth anything
if (!(await signed.verify({}, ctx))) throw new Error('VICAL signature is invalid')

const vical = signed.vical

vical.vicalProvider          // who published it
vical.date                   // when
vical.nextUpdate             // when to fetch again

vical.forDocType()           // entries listed for org.iso.18013.5.1.mDL
vical.forCountry('NL')       // the entry a country issued
vical.trustAnchors()         // Map<issuing country, CertificateInfo>
vical.certificates()         // raw DER, ready for an X.509 library
```

Handing a whole trust list to a verifier is the point of all this:

```ts
await Verifier.verifyDeviceResponse(
  { deviceResponse, sessionTranscript, trustedCertificates: vical.certificates() },
  ctx
)
```

## `SignedVical`

`SignedVical` extends `Sign1` from `@m-doc/core`, so the COSE surface —
`protectedHeaders`, `certificateChain`, `signatureAlgorithmName`, `toBeSigned` —
is all available on it.

```ts
class SignedVical extends Sign1 {
  static decode(bytes: Uint8Array): SignedVical

  get vical(): Vical      // decoded lazily from the payload

  verify(options: { key?: CoseKey }, ctx: Pick<MdocContext, 'cose' | 'x509'>): Promise<boolean>
}
```

`verify({}, ctx)` with no key takes the public key from the leaf of the
`x5chain` header, which establishes only that the list is internally consistent.
Pass the provider's known key — or validate the chain against a trust anchor of
your own — to learn that it is the list you meant to fetch.

Decoding failures raise `VicalError`, which carries the underlying cause.

## `Vical`

```ts
class Vical extends CborStructure {
  get version(): string                 // '1.0'
  get vicalProvider(): string
  get date(): Date
  get nextUpdate(): Date | undefined
  get vicalIssueID(): number | undefined   // monotonic issue counter
  get certificateInfos(): Array<CertificateInfo>
  get extensions(): Map<string, unknown> | undefined

  forDocType(docType?: string): Array<CertificateInfo>          // defaults to mDL
  forCountry(countryCode: string): CertificateInfo | undefined
  forSubjectKeyIdentifier(ski: Uint8Array): CertificateInfo | undefined
  trustAnchors(docType?: string): Map<string, CertificateInfo>  // keyed by issuing country
  certificates(docType?: string): Array<Uint8Array>
}
```

`trustAnchors` keeps the last entry where a country lists more than one
certificate for the docType; read `forDocType` where every entry matters.

A list past its `nextUpdate` is stale however valid its signature — check it
yourself, since nothing here will.

## `CertificateInfo`

```ts
for (const info of vical.forDocType()) {
  info.certificate           // DER-encoded IACA certificate
  info.toPem()               // the same, as a PEM block
  info.serialNumber          // bigint
  info.ski                   // Subject Key Identifier, as the provider wrote it
  info.docType               // Array<string> — what this CA may issue
  info.certificateProfile    // e.g. '1.0.18013.5.1.2'
  info.issuingAuthority
  info.issuingCountry
  info.stateOrProvinceName   // where a jurisdiction is a subdivision
  info.issuer, info.subject  // DER-encoded names
  info.notBefore, info.notAfter
  info.extensions
}
```

Also exported: `MDL_DOCTYPE`, `IACA_CERTIFICATE_PROFILE` (`1.0.18013.5.1.2`) and
`VICAL_EKU_OID` (`1.0.18013.5.1.8`).

## Round-tripping

Members the spec reserves for future use are carried through decoding untouched,
so a list from a newer provider still re-encodes to the bytes it arrived as —
which is what keeps its signature verifiable after a decode.

```ts
SignedVical.decode(bytes).encode()   // byte-identical to bytes
```

## Requirements

Node 20.19 or newer. Ships ESM and CJS, with type declarations for both. The
library itself is runtime-agnostic; only the CLI is Node-specific.

## License

Apache-2.0.
