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

Versions are set by hand in each package. Pushing a `v*` tag validates the
workspace and publishes every package whose version is not yet on the registry.

```bash
git tag v1.0.0 && git push origin v1.0.0
```

## License

Apache-2.0.
