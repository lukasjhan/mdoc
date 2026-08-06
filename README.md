<h1 align="center"><b>m-doc</b></h1>

<p align="center">
  mdoc / mDL (<a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5</a> &amp; 18013-7) for TypeScript.
</p>

ISO/IEC 18013-5 defines the mDL — a mobile driving licence — and the mdoc
format it is built on. This workspace holds the TypeScript implementation:
issuing, holding and verifying mdoc documents, in Node, the browser and React
Native.

- [Packages](#packages) · [Install](#install)
- [Quick start](#quick-start) — the whole round trip
- [Examples](#examples) — four runnable programs
- [Concepts](#concepts) — `MdocContext`, `CborStructure`
- [`@m-doc/core`](#m-doccore) — [issuing](#issuing) · [holding](#holding) · [verifying](#verifying) · [reading claims](#reading-claims) · [session transcripts](#session-transcripts) · [COSE](#cose) · [the CBOR layer](#the-cbor-layer)
- [`@m-doc/context`](#m-doccontext) · [`@m-doc/vical`](#m-docvical) · [`@m-doc/mdl`](#m-docmdl) · [`@m-doc/photo-id`](#m-docphoto-id)
- [What this library does not do](#what-this-library-does-not-do)
- [Playground](#playground) · [Development](#development) · [Releasing](#releasing)

## Packages

| Package | Description | Runtime dependencies |
| --- | --- | --- |
| [`@m-doc/core`](./packages/core) | The mdoc data model, COSE structures, issuing and verification | `cbor-x`, `zod` |
| [`@m-doc/context`](./packages/context) | WebCrypto and X.509 bindings, for Node, the browser and React Native | `@noble/*`, `@panva/hkdf`, `@peculiar/x509`, `jose` |
| [`@m-doc/vical`](./packages/vical) | VICAL — the ISO/IEC 18013-5 Annex C issuer trust list, with a `vical` CLI | `@m-doc/core`, `zod` |
| [`@m-doc/mdl`](./packages/mdl) | The mDL profile: element identifiers, age attestations, driving privileges | `@m-doc/core` |
| [`@m-doc/photo-id`](./packages/photo-id) | The ISO/IEC TS 23220-4 PhotoID profile: namespaces and element identifiers | none |

Every package ships ESM and CJS with type declarations for both, and requires
Node 20.19 or newer. `@m-doc/photo-id` is pure data and pulls in nothing at all.

## Install

```bash
npm install @m-doc/core @m-doc/context
# and, for a specific document profile
npm install @m-doc/mdl
```

## Quick start

An issuer signs a document, a holder presents two of its four elements, and a
verifier checks what came back. This is the whole flow; the sections below take
each step apart.

```ts
import {
  DeviceRequest, DeviceResponse, DocRequest,
  Holder, Issuer, ItemsRequest, SessionTranscript, SignatureAlgorithm,
} from '@m-doc/core'
import { createMdocContext } from '@m-doc/context'

const ctx = createMdocContext()

// 1. Issue
const issuerSigned = await new Issuer('org.iso.18013.5.1.mDL', ctx)
  .addIssuerNamespace('org.iso.18013.5.1', {
    family_name: 'Doe',
    given_name: 'Jane',
    age_over_18: true,
    document_number: 'NL-000123',
  })
  .sign({
    signingKey: issuerPrivateKey,          // CoseKey, or a JWK
    certificate: issuerCertificateBytes,   // DER
    algorithm: SignatureAlgorithm.ES256,
    digestAlgorithm: 'SHA-256',
    deviceKeyInfo: { deviceKey: devicePublicKey },
    validityInfo: { signed: now, validFrom: now, validUntil: inTenYears },
  })

// 2. Hold — check what you were issued before storing it
await Holder.verifyIssuerSigned({ issuerSigned, trustedCertificates: [issuerCertificateBytes] }, ctx)

// 3. Present — only what was asked for leaves the wallet
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
        docType: 'org.iso.18013.5.1.mDL',
        namespaces: { 'org.iso.18013.5.1': { family_name: false, age_over_18: false } },
      }),
    }),
  ],
})

const deviceResponse = await Holder.createDeviceResponseForDeviceRequest(
  {
    deviceRequest,
    sessionTranscript,
    issuerSigned: [issuerSigned],
    signature: { signingKey: devicePrivateKey },
  },
  ctx
)

// 4. Verify
const received = DeviceResponse.decode(deviceResponse.encode())
await received.verify({ trustedCertificates: [issuerCertificateBytes], sessionTranscript, deviceRequest }, ctx)

received.getAllPrettyClaims()['org.iso.18013.5.1.mDL']['org.iso.18013.5.1']
// { family_name: 'Doe', age_over_18: true } — given_name and document_number stayed behind
```

## Examples

[`examples/node`](./examples/node) holds four TypeScript programs, each one
runnable and each one about a single step. No build step — the workspace
packages resolve to their sources and `tsx` runs them directly.

```bash
pnpm install
cd examples/node

pnpm issue     # sign an mDL
pnpm present   # answer a request with a subset of it
pnpm verify    # check what came back, one named check at a time
pnpm vical     # read a real AAMVA trust list
```

| File | Shows |
| --- | --- |
| [`01-issue.ts`](./examples/node/src/01-issue.ts) | Claim types, `age_over_NN`, the MSO, a status list entry, reading back as CBOR and as JSON |
| [`02-present.ts`](./examples/node/src/02-present.ts) | Session transcripts, items requests, selective disclosure, `intentToRetain`, §7.2.5 age resolution |
| [`03-verify.ts`](./examples/node/src/03-verify.ts) | Every verification check, grouped by category, then the profile checks a signature cannot answer |
| [`04-vical.ts`](./examples/node/src/04-vical.ts) | Decoding and verifying a genuine AAMVA VICAL, and looking entries up by country, SKI and docType |

The same round trip as an assertion is in
[`packages/context/tests/end-to-end.test.ts`](./packages/context/tests/end-to-end.test.ts).

## Concepts

### `MdocContext`

`@m-doc/core` does no cryptography itself. Every operation that needs a
primitive takes an `MdocContext` as its last argument, and the parameter is
typed with only the slice it uses — `Pick<MdocContext, 'cose' | 'x509'>` — so a
partial context is enough when that is all you have.

```ts
interface MdocContext {
  crypto: {
    random(length: number): Uint8Array
    digest(input: { digestAlgorithm: DigestAlgorithm; bytes: Uint8Array }): MaybePromise<Uint8Array>
    calculateEphemeralMacKey(input: {
      privateKey: Uint8Array
      publicKey: Uint8Array
      sessionTranscriptBytes: Uint8Array
      info: 'EMacKey' | 'SKReader' | 'SKDevice'
    }): MaybePromise<CoseKey>
  }

  cose: {
    sign1: {
      sign(input: { sign1: Sign1; key: CoseKey }): MaybePromise<Uint8Array>
      verify(input: { sign1: Sign1; key: CoseKey }): MaybePromise<boolean>
    }
    mac0: {
      sign(input: { mac0: Mac0; key: CoseKey }): MaybePromise<Uint8Array>
      verify(input: { mac0: Mac0; key: CoseKey }): MaybePromise<boolean>
    }
  }

  x509: {
    getIssuerNameField(input: { certificate: Uint8Array; field: string }): string[]
    getPublicKey(input: { certificate: Uint8Array; alg: string }): MaybePromise<CoseKey>
    verifyCertificateChain(input: {
      trustedCertificates: Uint8Array[]
      x5chain: Uint8Array[]
      now?: Date
    }): MaybePromise<void>
    getCertificateData(input: { certificate: Uint8Array }): MaybePromise<{
      issuerName: string; subjectName: string; serialNumber: string
      thumbprint: string; notBefore: Date; notAfter: Date; pem: string
    }>
  }
}
```

`@m-doc/context` implements all of it against WebCrypto. Write your own for a
hardware-backed key, a curve it does not cover, or a platform binding that is
not WebCrypto.

### `CborStructure`

Every wire structure — `DeviceResponse`, `Sign1`, `CoseKey`, `Vical` — is a
`CborStructure`. A model declares its wire format once as a static zod codec,
and encoding, decoding and validation all follow from it.

```ts
class SomeStructure extends CborStructure {
  static schema: z.ZodType

  encodedStructure(): unknown          // the model, back as plain CBOR values
  encode(options?: { asDataItem?: boolean }): Uint8Array

  static fromEncodedStructure(structure: unknown): T
  static decode(bytes: Uint8Array, options?: CborDecodeOptions): T
}
```

Three properties of that layer are deliberate, and worth relying on:

- **Unknown keys survive.** A map key the schema does not name is kept as it
  arrived and written back out. A document from a newer profile round-trips
  without losing anything.
- **Wire order is preserved.** Re-encoding a decoded structure produces the
  same bytes, so a signature stays valid across a decode/encode cycle.
- **Absent optionals stay absent.** An optional field that was not on the wire
  is not written back as `null`.

Instances are immutable: the decoded map is held privately and exposed through
getters. A structure that does not match its schema raises `CborSchemaError`,
which carries the underlying zod issues so you can tell a malformed document
apart from an unsupported one.

```ts
try {
  DeviceResponse.decode(bytes)
} catch (error) {
  if (error instanceof CborSchemaError) console.log(error.structureName, error.issues)
}
```

## `@m-doc/core`

### Issuing

```ts
class Issuer {
  constructor(docType: DocType, ctx: Pick<MdocContext, 'cose' | 'crypto'>)

  addIssuerNamespace(namespace: Namespace, values: Record<string | number, unknown>): this

  sign(options: {
    signingKey: CoseKey | Record<string | number, unknown>   // a JWK is accepted
    algorithm: SignatureAlgorithm
    digestAlgorithm: 'SHA-256' | 'SHA-384' | 'SHA-512'
    validityInfo: ValidityInfo | { signed: Date; validFrom: Date; validUntil: Date; expectedUpdate?: Date }
    deviceKeyInfo: DeviceKeyInfo | { deviceKey: DeviceKey; keyAuthorizations?: KeyAuthorizations; keyInfo?: KeyInfo }
    certificate: Uint8Array                                  // DER; becomes the x5chain
    status?: Status | StatusOptions                          // IETF Token Status List
  }): Promise<IssuerSigned>
}
```

`addIssuerNamespace` may be called more than once, for a document spanning
several namespaces. Element values are ordinary JavaScript values: use
`DateOnly` for a `full-date`, `Date` for a `tdate`, and `Uint8Array` for a
`bstr`. Each element gets a random `digestID` and 32 random bytes of salt, and
the digests — not the values — go into the MSO the issuer signs. That is what
makes selective disclosure possible later.

Revocation is carried in `status`, per the IETF Token Status List binding:

```ts
.sign({ …, status: { statusList: { idx: 412, uri: 'https://issuer.example.com/statuslists/1' } } })
```

Handing the result to a wallet over OpenID4VCI:

```ts
issuerSigned.encodedForOid4Vci             // base64url string
IssuerSigned.fromEncodedForOid4Vci(string) // and back
```

### Holding

```ts
class Holder {
  // Check a document you were issued. Throws on the first failed check.
  static verifyIssuerSigned(options: {
    issuerSigned: Uint8Array | string | IssuerSigned   // a string is base64url, per OpenID4VCI
    trustedCertificates?: Array<Uint8Array>
    verificationCallback?: VerificationCallback
    now?: Date
    skewSeconds?: number
    disableCertificateChainValidation?: boolean
  }, ctx: Pick<MdocContext, 'cose' | 'x509'>): Promise<void>

  // Check the reader is who it claims to be, before answering
  static verifyDeviceRequest(options: {
    deviceRequest: Uint8Array | DeviceRequest
    sessionTranscript: Uint8Array | SessionTranscript
    verificationCallback?: VerificationCallback
  }, ctx: Pick<MdocContext, 'cose' | 'x509'>): Promise<void>

  // Answer it, disclosing only what was asked for
  static createDeviceResponseForDeviceRequest(options: {
    deviceRequest: DeviceRequest
    sessionTranscript: SessionTranscript | Uint8Array
    issuerSigned: Array<IssuerSigned>          // the wallet's documents; the matching docType is picked
    deviceNamespaces?: DeviceNamespaces        // self-asserted claims, if any
    signature?: { signingKey: CoseKey }        // DeviceSignature — OpenID4VP, DC API
    mac?: { ephemeralKey: CoseKey; signingKey: CoseKey }   // DeviceMac — proximity
  }, ctx: Pick<MdocContext, 'cose' | 'crypto'>): Promise<DeviceResponse>
}
```

Exactly one of `signature` and `mac` must be given; both or neither raises
`EitherSignatureOrMacMustBeProvidedError`. Selective disclosure is applied for
you — the response carries only the `IssuerSignedItem`s the request named, and
the issuer's signature still verifies because the MSO holds digests.

### Verifying

```ts
class Verifier {
  static verifyDeviceResponse(options: {
    deviceResponse: Uint8Array | DeviceResponse
    sessionTranscript: SessionTranscript | Uint8Array
    trustedCertificates: Uint8Array[]
    deviceRequest?: DeviceRequest       // also check the response answers the request
    ephemeralReaderKey?: CoseKey        // required for a DeviceMac response
    now?: Date                          // defaults to the current time
    skewSeconds?: number                // clock skew allowed on validity checks; 30 by default
    disableCertificateChainValidation?: boolean
    onCheck?: VerificationCallback
  }, ctx: Pick<MdocContext, 'cose' | 'x509' | 'crypto'>): Promise<void>
}
```

`deviceResponse.verify(options, ctx)` is the same call on the model.

Verification runs as a series of named checks, each reported to a callback. The
default throws `MdlError` on the first failure; pass your own to collect
everything instead of stopping at the first.

```ts
type VerificationAssessment = {
  status: 'PASSED' | 'FAILED' | 'WARNING'
  category: 'DOCUMENT_FORMAT' | 'DEVICE_AUTH' | 'ISSUER_AUTH' | 'DATA_INTEGRITY' | 'READER_AUTH'
  check: string
  reason?: string
}

const results: Array<VerificationAssessment> = []
await Verifier.verifyDeviceResponse({ …, onCheck: (item) => results.push(item) }, ctx)
```

What gets checked, by category:

| Category | Checks |
| --- | --- |
| `DOCUMENT_FORMAT` | `version` present, documents well formed, response answers the request |
| `ISSUER_AUTH` | MSO signature, X.509 chain to a trust anchor, `validFrom`/`validUntil`, `docType` agreement |
| `DATA_INTEGRITY` | every disclosed element's digest matches the MSO; `issuing_country` and `issuing_jurisdiction` match the DS certificate subject |
| `DEVICE_AUTH` | `DeviceSignature` or `DeviceMac` over the session transcript, against the `deviceKey` in the MSO |
| `READER_AUTH` | `ReaderAuth` over the items request, when the request carries one |

### Reading claims

Reading a claim usually means naming its namespace up front, which a verifier
does not always know — and a name that does not match yields `undefined` rather
than saying so. Both `IssuerSigned` and `DeviceResponse` can hand you
everything instead.

```ts
issuerSigned.namespaces                        // Array<Namespace> — what the document actually carries
issuerSigned.getPrettyClaims(namespace)        // PrettyClaims | undefined
issuerSigned.getAllPrettyClaims()              // Record<Namespace, PrettyClaims>
issuerSigned.getAllPrettyClaimsAsJson(options) // the same, JSON-safe

deviceResponse.getAllPrettyClaims()            // Record<DocType, Record<Namespace, PrettyClaims>>
deviceResponse.getAllPrettyClaimsAsJson(options)
```

Values come back as decoded CBOR: a `Uint8Array` for a portrait, a `DateOnly`
for a birth date, a `Map` for driving privileges. The `AsJson` variants run
them through `cborToJson`, whose conversion is lossy and deliberately so:

| CBOR | JSON |
| --- | --- |
| tstr | string |
| uint / nint | number |
| bignum | decimal string (JSON has no bigint) |
| non-finite float | `null`, as `JSON.stringify` does |
| bool | boolean |
| null / undefined | `null` |
| bstr | base64url string, or a `data:` URI |
| array | array |
| map | object; integer keys become decimal strings |
| `#6.1004` full-date | `"2026-02-19"` |
| `#6.0` tdate | `"2026-02-19T12:00:00Z"`, no fraction |

```ts
cborToJson(value, { bytes: 'dataUri' })   // 'base64url' by default
```

Two consequences: **map order can change**, since JavaScript objects list
integer-like keys first; and **distinct keys can collide**, since a map holding
both `1` and `"1"` renders both as `"1"`. Read the `Map` directly when either
matters.

### Session transcripts

The session transcript binds a presentation to the exchange it happened in.
Getting it wrong is the usual cause of a device signature that will not verify,
so each binding has a constructor of its own.

```ts
// OpenID4VP over a redirect
await SessionTranscript.forOid4Vp({ clientId, responseUri, nonce, jwkThumbprint? }, ctx)

// OpenID4VP over the W3C Digital Credentials API
await SessionTranscript.forOid4VpDcApi({ origin, nonce, jwkThumbprint? }, ctx)

// ISO/IEC 18013-7 Annex C `org-iso-mdoc` over the DC API
await SessionTranscript.forIsoMdocDcApi({ origin, encryptionInfoBase64Url }, ctx)

// ISO/IEC 18013-5 proximity, over QR
SessionTranscript.forQrHandover({ deviceEngagement, eReaderKey })
```

Two earlier bindings are kept, because wallets and verifiers on them are still
deployed:

```ts
// ISO/IEC TS 18013-7:2025 Annex B, which references OpenID4VP draft 18.
// The handover is [clientIdHash, responseUriHash, nonce], each hash taken
// over [value, mdocGeneratedNonce].
await SessionTranscript.forOid4VpDraft18(
  { clientId, responseUri, verifierGeneratedNonce, mdocGeneratedNonce },
  ctx
)

// The DC API handover of OpenID4VP draft 24, whose info is [origin, clientId, nonce]
await SessionTranscript.forOid4VpDcApiDraft24({ origin, clientId, nonce }, ctx)
```

An empty `mdocGeneratedNonce` is accepted: B.4.4 types it as a tstr, and
deployed verifiers do send one.

For QR handover the exact bytes matter — the session keys are derived over
them. Build `DeviceEngagement` and `EReaderKey` with `.decode()` rather than
their constructors; a decoded structure re-encodes to the bytes it arrived as.

Decoding a transcript recognises which of the handovers it holds without a
discriminator, by asking each candidate whether the structure is its own.

### COSE

```ts
class Sign1 extends CborStructure {
  static tag = 18

  get protectedHeaders(): ProtectedHeaders
  get unprotectedHeaders(): UnprotectedHeaders
  get payload(): Uint8Array | null
  get signature(): Uint8Array | undefined
  get detachedContent(): Uint8Array | undefined
  get externalAad(): Uint8Array | undefined

  get toBeSigned(): Uint8Array           // the Sig_structure, ready for a signer
  get certificateChain(): Array<Uint8Array>
  get certificate(): Uint8Array          // the leaf of the x5chain
  get signatureAlgorithmName(): string   // 'ES256', …

  withDetachedContent(content: Uint8Array): this
  sign(options: { signingKey: CoseKey }, ctx): Promise<this>          // returns a signed copy
  verifySignature(options: { key?: CoseKey }, ctx): Promise<boolean>  // key from the x5chain if omitted
}
```

`Mac0` mirrors it with `tag = 17`, `toBeAuthenticated`, `tag`, and
`authenticate()`. Both are immutable — signing returns a new instance rather
than mutating.

`IssuerAuth`, `DeviceSignature`, `ReaderAuth` and `SignedVical` are all `Sign1`
subclasses, so everything above is available on them. `IssuerAuth` adds
`.mobileSecurityObject`.

```ts
class CoseKey extends CborStructure {
  static fromJwk(jwk: Record<string, unknown>): CoseKey

  get keyType(): KeyType | string
  get keyId(): Uint8Array | string | undefined
  get algorithm(): string | number | undefined
  get curve(): Curve | undefined
  get x/y/d/k(): Uint8Array | undefined

  get publicKey(): Uint8Array   // raw, for a signer
  get privateKey(): Uint8Array
  get jwk(): Record<string, unknown>
}
```

Also exported: the `Header`, `SignatureAlgorithm`, `MacAlgorithm`,
`EncryptionAlgorithm`, `KeyType`, `KeyOps` and `Curve` enums, and
`ProtectedHeaders` / `UnprotectedHeaders`. `ProtectedHeaders` keeps the bytes it
was decoded from, because `toBeSigned` embeds them verbatim.

### The CBOR layer

The CBOR layer is public, because a package building its own structures on top
of this one — `@m-doc/vical`, say — declares them with it.

```ts
import { CborStructure, buildStructure, cborMap, cborStructure } from '@m-doc/core'

const schema = cborMap([
  ['version', z.string()],
  ['issuer', z.string()],
  ['certificates', z.array(cborStructure(CertificateInfo))],
  ['nextUpdate', z.date().optional()],
])

class MyStructure extends CborStructure {
  public static override schema = schema

  public constructor(options: MyOptions) {
    super(buildStructure([
      ['version', options.version],
      ['issuer', options.issuer],
      ['certificates', options.certificates],
      ['nextUpdate', options.nextUpdate],
    ]))
  }

  public get version(): string {
    return this.structure.get('version') as string
  }
}
```

| Helper | For |
| --- | --- |
| `cborMap(fields)` | a keyed struct; preserves unknown keys and wire order, omits absent optionals |
| `cborArray(fields)` | a fixed-position array with named positions |
| `cborDynamicMap(key, value)` | a map whose keys are data, not field names |
| `cborStructure(Class)` | a nested `CborStructure` |
| `cborDataItem(Class)` | a nested structure wrapped in tag 24 (`#6.24(bstr)`) |
| `buildStructure(entries)` | the constructor-side map, dropping `undefined` |
| `coerceNumericKeys(structure)` | `"0"` → `0`, for a peer that wrote integer labels as text |
| `asEntries(value)` | a `Map` or plain object, as a `Map` |

Also exported: `DataItem` (tag 24), `DateOnly` (tag 1004 `full-date`),
`cborEncode` / `cborDecode`, `addExtension` from `cbor-x`, and the `base64`,
`base64url`, `hex`, `bytesToString`, `stringToBytes`, `concatBytes` and
`compareBytes` helpers.

## `@m-doc/context`

```ts
import { createMdocContext } from '@m-doc/context'

const ctx = createMdocContext()                      // uses globalThis.crypto
const ctx = createMdocContext({ crypto: webcrypto }) // or one you supply
```

One function, returning a full `MdocContext`. It works unchanged in Node, the
browser and React Native provided WebCrypto is available, and throws at
construction when it is not. What it implements:

| Operation | Implementation |
| --- | --- |
| `sign1.sign` / `verify` | ECDSA P-256, compact signatures, `@noble/curves`. Verification accepts non-canonical (high-S) signatures, which do occur in the wild |
| `mac0.sign` / `verify` | HMAC-SHA-256, `@noble/hashes` |
| `calculateEphemeralMacKey` | ECDH P-256 → HKDF-SHA-256 over the session transcript digest |
| `digest` / `random` | WebCrypto `subtle.digest` and `getRandomValues` |
| `x509.*` | `@peculiar/x509` for parsing and chain building, `jose` for key import |

**This context is ES256-only.** `SignatureAlgorithm` in core names EdDSA,
ES384/512, PS256/384/512 and RS256/384/512, but this implementation covers P-256
alone. Supply your own `MdocContext` for anything else.

`verifyCertificateChain` builds the chain, requires a presented certificate to
equal one of the trust anchors, then verifies each link's signature and validity
period. **Trust anchors should be roots (IACA), not leaves**: trusting a leaf
directly degenerates to an equality check and skips the validity period.

## `@m-doc/vical`

VICAL is the ISO/IEC 18013-5 Annex C trust list: a COSE_Sign1 over a list of
IACA certificates a verifier should trust.

```ts
import { SignedVical } from '@m-doc/vical'

const signed = SignedVical.decode(bytes)
await signed.verify({}, ctx)          // key from the x5chain leaf, or pass { key }

const vical = signed.vical
vical.version           // '1.0'
vical.vicalProvider     // the organisation that published it
vical.date              // when it was issued
vical.nextUpdate        // when to fetch it again, if given
vical.vicalIssueID      // monotonic issue counter, if given
vical.certificateInfos  // Array<CertificateInfo>

vical.forDocType('org.iso.18013.5.1.mDL')   // entries valid for a docType
vical.forCountry('NL')                      // by issuing country
vical.forSubjectKeyIdentifier(ski)          // by SKI
vical.trustAnchors(docType)                 // Map<issuing country, CertificateInfo>
vical.certificates(docType)                 // Array<Uint8Array>
```

Reading one from the command line, signature checked:

```bash
npx @m-doc/vical vical.cbor
npx @m-doc/vical --pem vical.cbor > anchors.pem
```

Feeding a verifier straight from a trust list:

```ts
await Verifier.verifyDeviceResponse({ …, trustedCertificates: vical.certificates() }, ctx)
```

`CertificateInfo` exposes `certificate`, `serialNumber` (a `bigint`), `ski`,
`docType`, `certificateProfile`, `issuingAuthority`, `issuingCountry`,
`stateOrProvinceName`, `issuer`, `subject`, `notBefore`, `notAfter`,
`extensions`, and `toPem()`.

Also exported: `MDL_DOCTYPE`, `IACA_CERTIFICATE_PROFILE`, `VICAL_EKU_OID` and
`VicalError`.

## `@m-doc/mdl`

The mDL profile — the knowledge in ISO/IEC 18013-5 clause 7 that a generic mdoc
library has no business hard-coding. It defines no value models of its own; it
is constants, types and functions over the claims you already have.

```ts
import {
  MDL_DOC_TYPE, MDL_NAMESPACE, MDL_MANDATORY_ELEMENTS, MDL_OPTIONAL_ELEMENTS,
  MDL_ELEMENT_ENCODING, encodingFor, jurisdictionNamespace,
  Sex, EYE_COLOURS, HAIR_COLOURS,
} from '@m-doc/mdl'

MDL_DOC_TYPE                       // 'org.iso.18013.5.1.mDL'
MDL_NAMESPACE                      // 'org.iso.18013.5.1'
jurisdictionNamespace('US-IA')     // 'org.iso.18013.5.1.US-IA'

encodingFor('birth_date')          // 'full-date'
encodingFor('portrait')            // 'bstr'
encodingFor('issue_date')          // 'tdate-or-full-date' — Table 5 allows either
encodingFor('age_over_65')         // 'bool' — any NN, not only the listed ones
encodingFor('org.example.custom')  // undefined
```

**Age attestations.** A request for `age_over_18` does not mean "give me the
element called `age_over_18`". Clause 7.2.5 defines a resolution: the nearest
TRUE attestation at or above the requested age; failing that the nearest FALSE
one at or below it; failing that, nothing. An mDL holding only `age_over_21:
true` should still answer a request for 18.

```ts
readAgeAttestations(claims)          // Array<{ identifier, age, value }>
resolveAgeAttestation(claims, 18)    // the one to answer with, or undefined
buildAgeAttestations('1990-04-12', validFrom, [18, 21])
// { age_over_18: true, age_over_21: true } — evaluated at the MSO's validFrom, as 7.2.5 requires
ageAt(birthDate, at)                 // whole years
parseAgeOverIdentifier('age_over_18')  // 18, or undefined
```

**Driving privileges.** Clause 7.2.4 — a `driving_privileges` value is an array
of CBOR maps, not something you want to reach into by hand.

```ts
readDrivingPrivileges(claims.driving_privileges)  // Array<DrivingPrivilege>
privilegesFor(claims.driving_privileges, 'B')     // just the category-B entries
```

**Profile checks.**

```ts
findMissingMandatoryElements(claims)  // Array<MdlMandatoryElementIdentifier>
isExpired(claims, now)                // boolean | undefined — undefined when expiry_date is absent
isNotYetValid(claims, now)
```

## `@m-doc/photo-id`

The ISO/IEC TS 23220-4 Annex C PhotoID profile, in the same shape as
`@m-doc/mdl`, with no runtime dependencies at all.

```ts
import {
  PHOTO_ID_DOC_TYPE, PHOTO_ID_BASE_NAMESPACE, PHOTO_ID_NAMESPACE, PHOTO_ID_DATAGROUPS_NAMESPACE,
  PHOTO_ID_MANDATORY_ELEMENTS, PHOTO_ID_RECOMMENDED_ELEMENTS, PHOTO_ID_OPTIONAL_ELEMENTS,
  PHOTO_ID_SPECIFIC_ELEMENTS, PHOTO_ID_ELEMENT_ENCODING, encodingFor,
  findMissingMandatoryElements, findTravelDocumentIssues, Sex,
} from '@m-doc/photo-id'
```

A PhotoID spans three namespaces: `org.iso.23220.1` for the elements ISO/IEC TS
23220-2 defines, `org.iso.23220.photoid.1` for the ones the profile adds, and
`org.iso.23220.datagroups.1` for ICAO 9303 data groups.

`findTravelDocumentIssues` covers the conditional rule Table C.2 puts on the
travel-document elements: where `dg1` is present, `travel_document_type` and
`travel_document_mrz` shall be too. The two live in different namespaces, so it
takes both sets of claims.

```ts
findTravelDocumentIssues({ photoIdClaims, dataGroupClaims })
// [{ element: 'travel_document_mrz', reason: 'travel_document_mrz is required when dg1 is present' }]
```

`Sex` follows ISO/IEC 5218, with the profile's note that `9` means X rather
than "not applicable".

## What this library does not do

Worth knowing before you plan around it:

- **No transport.** `DeviceEngagement`, `DeviceRetrievalMethod`, `BleOptions`,
  `NfcOptions` and `WifiOptions` are modelled, encoded and decoded — but this
  library moves no bytes. BLE, NFC and Wi-Fi Aware are yours to drive.
- **No session encryption.** `SessionEstablishment` and `SessionData` are
  modelled; the AES-GCM session encryption of clause 9.1.1.5 is not implemented.
  `calculateEphemeralMacKey` derives `SKReader`/`SKDevice`, so the key agreement
  is there to build on.
- **The bundled context is ES256-only.** See [`@m-doc/context`](#m-doccontext).
- **No certificate issuance.** Generating IACA roots and document-signer
  certificates is out of scope; use `@peculiar/x509` or your CA.
- **No revocation lookup.** The MSO's `status` is read and written, but fetching
  a status list and checking a bit is the caller's job.
- **`cborToJson` is lossy.** It is a convenience for handing claims to something
  that speaks JSON, not a round trip. Read the `Map` when order or key types
  matter.

## Playground

[`examples/playground`](./examples/playground) is a React app that decodes,
issues and presents documents in the browser — a jwt.io for mdoc. Everything
runs client side; no document, key or certificate leaves the tab.

```bash
pnpm --filter @m-doc/playground dev
```

## Development

```bash
pnpm install
pnpm build         # every package
pnpm test
pnpm types:check
pnpm style:check
```

A single package:

```bash
pnpm --filter @m-doc/core test
```

Packages depend on each other's `src` during development and on `dist` once
published, so there is no build step between editing a package and testing its
dependants.

## Releasing

**Every package shares one version.** A release bumps all of them together,
whether or not each one changed, so `@m-doc/core@1.1.0` and `@m-doc/mdl@1.1.0`
are always the pair that were built and tested against each other. Cross-package
dependencies are published as `^`, so a patch never forces a duplicate copy into
a dependency tree.

Versions are set by hand. Publishing sends up every package whose version is not
yet on the registry:

```bash
pnpm release
```

That runs `release:check` first — it builds, packs each package with pnpm, and
runs [publint](https://publint.dev) and
[are-the-types-wrong](https://arethetypeswrong.github.io) against the real
tarballs. Nothing is published unless all of it passes.

Use pnpm, not npm. `exports` points at `src/index.ts` during development and is
replaced with the `dist` map by `publishConfig.exports`, which is a pnpm
feature; npm ignores it and would publish a package pointing at a file it did
not ship. A `prepack` guard refuses to run under npm for that reason.

## License

Apache-2.0.

This library began as a fork of
[openwallet-foundation-labs/mdoc-ts](https://github.com/openwallet-foundation-labs/mdoc-ts)
and has since diverged.
