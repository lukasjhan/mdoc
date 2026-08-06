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

## Installation

```bash
npm i @m-doc/vical
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
vical.trustAnchors()         // Map<countryCode, CertificateInfo>
vical.certificates()         // raw DER, ready for an X.509 library
```

`verify({}, ctx)` with no key takes the public key from the leaf of the
`x5chain` header, which establishes only that the list is internally
consistent. Pass the provider's known key — or validate the chain against a
trust anchor of your own — to learn that it is the list you meant to fetch.

## Entries

```ts
for (const info of vical.forDocType()) {
  info.certificate           // DER-encoded IACA certificate
  info.toPem()               // the same, as a PEM block
  info.serialNumber          // bigint
  info.ski                   // Subject Key Identifier
  info.issuingCountry
  info.notBefore, info.notAfter
}
```

Members the spec reserves for future use are carried through decoding
untouched, so a list from a newer provider still re-encodes to the bytes it
arrived as.

## License

Apache-2.0.
