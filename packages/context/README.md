<h1 align="center"><b>@m-doc/context</b></h1>

<p align="center">
  <a href="https://www.npmjs.com/package/@m-doc/context">
    <img src="https://img.shields.io/npm/v/@m-doc/context" />
  </a>
</p>

[`@m-doc/core`](../core) does no cryptography itself. It takes an `MdocContext`
holding the primitives it needs — hashing, ECDH, COSE signing, X.509 chain
validation — so an application can bind it to whatever its platform provides.

This package is a ready-made one, built on WebCrypto, [`@noble/curves`](https://github.com/paulmillr/noble-curves)
and [`@peculiar/x509`](https://github.com/PeculiarVentures/x509). Nothing in it
is Node-specific: the same implementation runs in the browser, and in React
Native with a WebCrypto polyfill.

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
browser provide. Where the runtime has no global, pass one in:

```ts
import { polyfillWebCrypto } from 'my-react-native-polyfill'

const ctx = createMdocContext({ crypto: polyfillWebCrypto })
```

## What it implements

| Group | Backed by |
| --- | --- |
| `crypto.digest` · `crypto.random` | WebCrypto |
| `crypto.calculateEphemeralMacKey` | `@noble/curves` ECDH + `@panva/hkdf` |
| `cose.sign1` | `@noble/curves` P-256 |
| `cose.mac0` | `@noble/hashes` HMAC-SHA256 |
| `x509.*` | `@peculiar/x509`, with `jose` for public-key import |

## License

Apache-2.0.
