<h1 align="center"><b>@m-doc/photo-id</b></h1>

<p align="center">
  <a href="https://www.npmjs.com/package/@m-doc/photo-id">
    <img src="https://img.shields.io/npm/v/@m-doc/photo-id" />
  </a>
</p>

The PhotoID profile of ISO/IEC TS 23220-4:2026 Annex C: its namespaces, its
element identifiers and encodings, and the conditional rule Table C.2 puts on
the travel-document elements.

[`@m-doc/core`](https://www.npmjs.com/package/@m-doc/core) reads and writes the
document; this package says what belongs in it. It is pure data and functions,
with **no runtime dependencies at all** — not even on `@m-doc/core`.

Part of [**m-doc**](https://github.com/lukasjhan/mdoc). The
[browser playground](https://mdoc-playground.vercel.app) issues PhotoIDs with
it.

## Installation

```bash
npm i @m-doc/photo-id
```

## Namespaces

A PhotoID spreads its elements across three namespaces, which is the part worth
knowing before reading claims:

```ts
import {
  PHOTO_ID_DOC_TYPE,               // 'org.iso.23220.photoid.1'
  PHOTO_ID_BASE_NAMESPACE,         // 'org.iso.23220.1'         — Table C.1, from 23220-2
  PHOTO_ID_NAMESPACE,              // 'org.iso.23220.photoid.1' — Table C.2, PhotoID's own
  PHOTO_ID_DATAGROUPS_NAMESPACE,   // 'org.iso.23220.datagroups.1' — ICAO 9303 data groups
  jurisdictionNamespace,           // jurisdictionNamespace('US-IA') → 'org.iso.23220.photoid.US-IA.1'
} from '@m-doc/photo-id'
```

Data groups are left as bytes: parsing ICAO 9303 is a separate concern.

## Element identifiers and encodings

```ts
import {
  PHOTO_ID_MANDATORY_ELEMENTS,     // Table C.1, presence M
  PHOTO_ID_RECOMMENDED_ELEMENTS,   // Table C.1 recommends these
  PHOTO_ID_OPTIONAL_ELEMENTS,      // Table C.1, presence O
  PHOTO_ID_SPECIFIC_ELEMENTS,      // Table C.2 — PhotoID's own
  PHOTO_ID_ELEMENT_ENCODING,
  encodingFor,
  Sex,
} from '@m-doc/photo-id'

encodingFor('family_name')     // 'tstr'
encodingFor('birth_date')      // 'full-date'
encodingFor('portrait')        // 'bstr'
encodingFor('sex')             // 'uint'
encodingFor('age_over_18')     // 'bool' — any NN
```

`Sex` follows ISO/IEC 5218, with the profile's note that `9` means X rather than
"not applicable":

```ts
Sex.NotKnown  // 0
Sex.Male      // 1
Sex.Female    // 2
Sex.X         // 9
```

The identifier types are exported too — `PhotoIdBaseElementIdentifier`,
`PhotoIdMandatoryElementIdentifier`, `PhotoIdSpecificElementIdentifier`,
`PhotoIdEncoding`, `SexValue`.

## Profile checks

```ts
import { findMissingMandatoryElements, findTravelDocumentIssues } from '@m-doc/photo-id'

// Table C.1, presence M — against the base-namespace claims
findMissingMandatoryElements(baseClaims)

// Table C.2 makes these conditional: required once dg1 is present
findTravelDocumentIssues({ photoIdClaims, dataGroupClaims })
// → [{ element: 'travel_document_mrz', reason: 'travel_document_mrz is required when dg1 is present' }]
```

`findTravelDocumentIssues` takes both sets of claims because the condition spans
namespaces: `dg1` lives in the data-group namespace and the two elements it
requires live in the PhotoID namespace. With no `dg1`, they are optional and it
returns nothing.

`findMissingMandatoryElements` is a finding on a document that was meant to be
complete. A presented PhotoID is allowed to disclose a subset.

## Requirements

Node 20.19 or newer. Ships ESM and CJS, with type declarations for both.

## License

Apache-2.0.
