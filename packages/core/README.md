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
Native.

## Installation

```bash
npm i @m-doc/core
```

## Reading claims

A decoded response exposes its claims without you having to name the docType or
namespace first:

```ts
const document = DeviceResponse.decode(bytes).documents?.[0]

document.namespaces              // ['eu.europa.ec.eudi.pid.1']
document.getPrettyClaims(ns)     // one namespace
document.getAllPrettyClaims()    // every namespace, keyed by namespace
```

Values come back as decoded CBOR — a byte string is a `Uint8Array`, a map is a
`Map`, a full-date is a `DateOnly`. To hand them to something that speaks JSON,
ask for the JSON view instead:

```ts
document.getAllPrettyClaimsAsJson()
// { 'eu.europa.ec.eudi.pid.1': { family_name: 'Han', birth_date: '2026-02-19', … } }

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

## License

Apache-2.0.

## Credits

Thanks to:

- [auth0/mdl](https://github.com/auth0-lab/mdl) for the mdl implementation this repository started from.
- [animo-id/mdoc](https://github.com/openwallet-foundation-labs/mdoc-ts) for the rework this fork is based on.
- [auer-martin](https://github.com/auer-martin) for removing the Node.js dependencies and providing a pluggable crypto interface.
