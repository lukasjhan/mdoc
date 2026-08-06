<h1 align="center"><b>m-doc</b></h1>

<p align="center">
  mdoc / mDL (<a href="https://www.iso.org/standard/69084.html">ISO/IEC 18013-5</a> &amp; 18013-7) for TypeScript.
</p>

ISO/IEC 18013-5 defines the mDL — a mobile driving licence — and the mdoc
format it is built on. This workspace holds the TypeScript implementation:
issuing, holding and verifying mdoc documents, in Node, the browser and React
Native.

## Packages

| Package | Description |
| --- | --- |
| [`@m-doc/core`](./packages/core) | The mdoc data model, COSE structures, issuing and verification |
| [`@m-doc/context`](./packages/context) | WebCrypto and X.509 bindings, for Node, the browser and React Native |

`@m-doc/core` does no cryptography itself — it takes an `MdocContext` holding
the primitives it needs. `@m-doc/context` is a ready-made one:

```ts
import { createMdocContext } from '@m-doc/context'

const ctx = createMdocContext()
await DeviceResponse.decode(bytes).verify({ trustedCertificates, sessionTranscript }, ctx)
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

## Releasing

Versions are set by hand in each package. Publishing is manual, and sends up
every package whose version is not yet on the registry.

```bash
pnpm release
```

## License

Apache-2.0.
