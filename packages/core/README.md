<h1 align="center"><b>@m-doc/core</b></h1>

<p align="center">
  <a href="https://typescriptlang.org">
    <img src="https://img.shields.io/badge/%3C%2F%3E-TypeScript-%230074c1.svg" />
  </a>
  <a href="https://www.npmjs.com/package/@m-doc/core">
    <img src="https://img.shields.io/npm/v/@m-doc/core" />
  </a>
</p>

[ISO/IEC 18013-5](https://www.iso.org/standard/69084.html) defines the mDL — a
mobile driving licence — and the mdoc format it is built on. This package
issues, holds and verifies mdoc documents, in Node, the browser and React
Native. It depends only on `cbor-x` and `zod`, and does no cryptography itself.

**Runnable examples:**
[issue](https://github.com/lukasjhan/mdoc/blob/main/examples/node/src/01-issue.ts) ·
[present](https://github.com/lukasjhan/mdoc/blob/main/examples/node/src/02-present.ts) ·
[verify](https://github.com/lukasjhan/mdoc/blob/main/examples/node/src/03-verify.ts) ·
[VICAL](https://github.com/lukasjhan/mdoc/blob/main/examples/node/src/04-vical.ts)
· or the [browser playground](https://mdoc-playground.vercel.app).

Companion packages:
[`@m-doc/context`](https://www.npmjs.com/package/@m-doc/context) (crypto
bindings) ·
[`@m-doc/vical`](https://www.npmjs.com/package/@m-doc/vical) (trust lists) ·
[`@m-doc/mdl`](https://www.npmjs.com/package/@m-doc/mdl) and
[`@m-doc/photo-id`](https://www.npmjs.com/package/@m-doc/photo-id) (document
profiles).

## Installation

```bash
npm i @m-doc/core @m-doc/context
```

## The round trip

An issuer signs a document, a holder presents two of its four elements, and a
verifier checks what came back.

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
  { deviceRequest, sessionTranscript, issuerSigned: [issuerSigned], signature: { signingKey: devicePrivateKey } },
  ctx
)

// 4. Verify
const received = DeviceResponse.decode(deviceResponse.encode())
await received.verify({ trustedCertificates: [issuerCertificateBytes], sessionTranscript, deviceRequest }, ctx)

received.getAllPrettyClaims()['org.iso.18013.5.1.mDL']['org.iso.18013.5.1']
// { family_name: 'Doe', age_over_18: true } — given_name and document_number stayed behind
```

## `MdocContext`

This package does **no cryptography itself**. Every operation that needs a
primitive takes an `MdocContext` as its last argument, typed with only the slice
it uses — `Pick<MdocContext, 'cose' | 'x509'>` — so a partial context is enough
when that is all you have.

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

## Issuing

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

## Holding

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

## Verifying

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

[`03-verify.ts`](https://github.com/lukasjhan/mdoc/blob/main/examples/node/src/03-verify.ts)
prints all of them.

## Reading claims

Reading a claim usually means naming its namespace up front, which a verifier
does not always know — and a name that does not match yields `undefined` rather
than saying so. `Document`, `IssuerSigned` and `DeviceResponse` can hand you
everything instead.

```ts
const document = DeviceResponse.decode(bytes).documents?.[0]

document.namespaces              // ['eu.europa.ec.eudi.pid.1']
document.getPrettyClaims(ns)     // one namespace
document.getAllPrettyClaims()    // every namespace, keyed by namespace

deviceResponse.getAllPrettyClaims()   // Record<DocType, Record<Namespace, PrettyClaims>>
```

Values come back as decoded CBOR — a byte string is a `Uint8Array`, a map is a
`Map`, a full-date is a `DateOnly`. To hand them to something that speaks JSON,
ask for the JSON view instead:

```ts
document.getAllPrettyClaimsAsJson()
// { 'eu.europa.ec.eudi.pid.1': { family_name: 'Doe', birth_date: '2026-02-19', … } }

document.getAllPrettyClaimsAsJson({ bytes: 'dataUri' })
// portrait: 'data:application/octet-stream;base64,…'

cborToJson(value)                // the same conversion, for any CBOR value
```

The conversion is lossy, because JSON has no byte string, no integer-keyed map
and no date:

| CBOR | JSON |
| --- | --- |
| tstr | string |
| uint / nint | number |
| bignum | decimal string |
| non-finite float | `null` |
| bool | boolean |
| null / undefined | `null` |
| bstr | base64url string, or a data URI with `{ bytes: 'dataUri' }` |
| array | array |
| map | object; integer keys become decimal strings |
| `#6.1004` full-date | `"2026-02-19"` |
| `#6.0` tdate | `"2026-02-19T12:00:00Z"`, no fraction of a second |

Two consequences worth knowing:

- **Map order can change.** JavaScript objects list integer-like keys first, so
  a map keyed `{"zeta", 1, "alpha", 0}` comes back as `{"0", "1", "zeta",
  "alpha"}`. Read the `Map` directly if order matters.
- **Distinct keys can collide.** A map holding both `1` and `"1"` loses one of
  them, since both render as `"1"`.

## Session transcripts

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

For QR handover the exact bytes matter — the session keys are derived over them.
Build `DeviceEngagement` and `EReaderKey` with `.decode()` rather than their
constructors; a decoded structure re-encodes to the bytes it arrived as.

Decoding a transcript recognises which of the handovers it holds without a
discriminator, by asking each candidate whether the structure is its own.

## COSE

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

`IssuerAuth`, `DeviceSignature` and `ReaderAuth` are `Sign1` subclasses, so
everything above is available on them. `IssuerAuth` adds `.mobileSecurityObject`.

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

## The CBOR layer

Every wire structure — `DeviceResponse`, `Sign1`, `CoseKey` — is a
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
- **Wire order is preserved.** Re-encoding a decoded structure produces the same
  bytes, so a signature stays valid across a decode/encode cycle.
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

The layer is public, because a package building its own structures on top of
this one — [`@m-doc/vical`](https://www.npmjs.com/package/@m-doc/vical), say —
declares them with it.

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

## What this package does not do

- **No transport.** `DeviceEngagement`, `DeviceRetrievalMethod`, `BleOptions`,
  `NfcOptions` and `WifiOptions` are modelled, encoded and decoded — but this
  library moves no bytes. BLE, NFC and Wi-Fi Aware are yours to drive.
- **No session encryption.** `SessionEstablishment` and `SessionData` are
  modelled; the AES-GCM session encryption of clause 9.1.1.5 is not implemented.
  `calculateEphemeralMacKey` derives `SKReader`/`SKDevice`, so the key agreement
  is there to build on.
- **No cryptography.** That is the `MdocContext`'s job, by design.
- **No certificate issuance.** Generating IACA roots and document-signer
  certificates is out of scope.
- **No revocation lookup.** The MSO's `status` is read and written, but fetching
  a status list and checking a bit is the caller's job.

## Requirements

Node 20.19 or newer. Ships ESM and CJS, with type declarations for both.

## License

Apache-2.0.
