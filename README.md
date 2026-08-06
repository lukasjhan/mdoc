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

Each package can also be worked on directly:

```bash
pnpm --filter @m-doc/core test
```

## Contributing

Is there something you'd like to fix or add? Great, we love community
contributions! To get involved, please follow our [contribution guidelines](./CONTRIBUTING.md).

## License

This project is licensed under the Apache License Version 2.0 (Apache-2.0).
