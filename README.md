<p align="center">
  <picture>
   <source media="(prefers-color-scheme: light)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656578320/animo-logo-light-no-text_ok9auy.svg">
   <source media="(prefers-color-scheme: dark)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656578320/animo-logo-dark-no-text_fqqdq9.svg">
   <img alt="Animo Logo" height="250px" />
  </picture>
</p>

<h1 align="center" ><b>mDOC and mDL - TypeScript</b></h1>

[ISO 18013-5](https://www.iso.org/standard/69084.html) defines mDL (mobile Driver’s Licenses): an ISO standard for digital driver licenses.

This is a JavaScript library for Node.JS, browers and React Native to issue and verify mDL [CBOR encoded](https://cbor.io/) documents in accordance with **ISO 18013-7 (draft's date: 2024-03-12)**.

<h4 align="center">Powered by &nbsp; 
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656579715/animo-logo-light-text_cma2yo.svg">
    <source media="(prefers-color-scheme: dark)" srcset="https://res.cloudinary.com/animo-solutions/image/upload/v1656579715/animo-logo-dark-text_uccvqa.svg">
    <img alt="Animo Logo" height="12px" />
  </picture>
</h4><br>

<p align="center">
  <a href="https://typescriptlang.org">
    <img src="https://img.shields.io/badge/%3C%2F%3E-TypeScript-%230074c1.svg" />
  </a>
  <a href="https://www.npmjs.com/package/@animo-id/mdoc">
    <img src="https://img.shields.io/npm/v/@animo-id/mdoc" />
  </a>
</p>

<p align="center">
  <a href="#installation">Installation</a> 
  &nbsp;|&nbsp;
  <a href="#contributing">Contributing</a>
  &nbsp;|&nbsp;
  <a href="#license">License</a>
  &nbsp;|&nbsp;
  <a href="#credits">Credits</a>
</p>

## Installation

```bash
npm i @animo-id/mdoc
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

## Contributing

Is there something you'd like to fix or add? Great, we love community
contributions! To get involved, please follow our [contribution guidelines](./CONTRIBUTING.md).

## License

This project is licensed under the Apache License Version 2.0 (Apache-2.0).

## Credits

Thanks to:

- [auth0/mdl](https://github.com/auth0-lab/mdl) for the mdl implementation on which this repository is based.
- [auer-martin](https://github.com/auer-martin) for removing node.js dependencies and providing a pluggable crypto interface
