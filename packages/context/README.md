<h1 align="center"><b>@m-doc/context</b></h1>

<p align="center">
  <a href="https://www.npmjs.com/package/@m-doc/context">
    <img src="https://img.shields.io/npm/v/@m-doc/context" />
  </a>
</p>

[`@m-doc/core`](https://www.npmjs.com/package/@m-doc/core) does no cryptography
itself. It takes an `MdocContext` holding the primitives it needs — hashing,
ECDH, COSE signing, X.509 chain validation — so an application can bind it to
whatever its platform provides.

This package is a ready-made one, built on WebCrypto,
[`@noble/curves`](https://github.com/paulmillr/noble-curves) and
[`@peculiar/x509`](https://github.com/PeculiarVentures/x509). Nothing in it is
Node-specific: the same implementation runs in the browser, and in React Native
with a WebCrypto polyfill.

Part of [**m-doc**](https://github.com/lukasjhan/mdoc). Every
[runnable example](https://github.com/lukasjhan/mdoc/tree/main/examples/node)
starts by creating one of these.

## Installation

```bash
npm i @m-doc/context
```

## Usage

```ts
import { createMdocContext } from '@m-doc/context'

const ctx = createMdocContext()

await DeviceResponse.decode(bytes).verify({ trustedCertificates, sessionTranscript }, ctx)
```

`createMdocContext` reads `globalThis.crypto`, which Node 20 and every current
browser provide, and throws at construction where there is none. Pass one in
where the runtime has no global:

```ts
import { polyfillWebCrypto } from 'my-react-native-polyfill'

const ctx = createMdocContext({ crypto: polyfillWebCrypto })
```

That is the whole API:

```ts
type MdocContextOptions = { crypto?: WebCrypto }

const createMdocContext: (options?: MdocContextOptions) => MdocContext
```

## What it implements

| Operation | Implementation |
| --- | --- |
| `cose.sign1.sign` / `verify` | ECDSA P-256, compact signatures, `@noble/curves` |
| `cose.mac0.sign` / `verify` | HMAC-SHA-256, `@noble/hashes` |
| `crypto.calculateEphemeralMacKey` | ECDH P-256 → HKDF-SHA-256 over the session transcript digest, `@panva/hkdf` |
| `crypto.digest` / `crypto.random` | WebCrypto `subtle.digest` and `getRandomValues` |
| `x509.*` | `@peculiar/x509` for parsing and chain building, `jose` for public-key import |

## Two things to know

**This context is ES256-only.** `SignatureAlgorithm` in `@m-doc/core` names
EdDSA, ES384/512, PS256/384/512 and RS256/384/512, but this implementation
covers P-256 alone. Supply your own `MdocContext` for anything else — that is
what the interface is for.

Signature verification deliberately accepts non-canonical (high-S) signatures,
because they do occur in the wild.

**Trust anchors should be roots, not leaves.** `verifyCertificateChain` builds
the chain, requires a presented certificate to equal one of the trust anchors,
then verifies each link's signature and validity period. Passing a document
signer as its own anchor degenerates to an equality check, and skips the
validity period along with it. Anchor on IACA roots — a
[VICAL](https://www.npmjs.com/package/@m-doc/vical) is where you get them.

## Requirements

Node 20.19 or newer, or any runtime with WebCrypto. Ships ESM and CJS, with
type declarations for both.

## License

Apache-2.0.
