<h1 align="center"><b>@m-doc/photo-id</b></h1>

<p align="center">
  <a href="https://www.npmjs.com/package/@m-doc/photo-id">
    <img src="https://img.shields.io/npm/v/@m-doc/photo-id" />
  </a>
</p>

The PhotoID profile of ISO/IEC TS 23220-4:2026 Annex C: its namespaces, its
element identifiers, and the conditional rule Table C.2 puts on the
travel-document elements.

[`@m-doc/core`](../core) reads and writes the document; this package says what
belongs in it. It has no runtime dependencies.

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

## Profile checks

```ts
import { findMissingMandatoryElements, findTravelDocumentIssues } from '@m-doc/photo-id'

// Table C.1, presence M — against the base-namespace claims
findMissingMandatoryElements(baseClaims)

// Table C.2 makes these conditional: required once dg1 is present
findTravelDocumentIssues({ photoIdClaims, dataGroupClaims })
// → [{ element: 'travel_document_mrz', reason: '…' }]
```

`findMissingMandatoryElements` is a finding on a document that was meant to be
complete. A presented PhotoID is allowed to disclose a subset.

## License

Apache-2.0.
