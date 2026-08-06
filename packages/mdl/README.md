<h1 align="center"><b>@m-doc/mdl</b></h1>

<p align="center">
  <a href="https://www.npmjs.com/package/@m-doc/mdl">
    <img src="https://img.shields.io/npm/v/@m-doc/mdl" />
  </a>
</p>

The mDL profile of [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html):
what its element identifiers are, how each one is encoded, and the handful of
rules that are easy to get wrong when issuing or verifying one.

[`@m-doc/core`](https://www.npmjs.com/package/@m-doc/core) reads and writes the
document; this package says what belongs in it. It defines no value models of
its own — everything here is constants, types and functions over the claims you
already have.

Part of [**m-doc**](https://github.com/lukasjhan/mdoc). Used throughout the
[runnable examples](https://github.com/lukasjhan/mdoc/tree/main/examples/node).

## Installation

```bash
npm i @m-doc/mdl
```

## Age attestations

An mDL conveys age without revealing a date of birth, through `age_over_NN`
elements. §7.2.5 defines what a request for one means, and it is not "return the
element with that name":

> provide the nearest age attestation equal to or larger than NN with value
> TRUE, or smaller than NN with value FALSE

```ts
import { resolveAgeAttestation } from '@m-doc/mdl'

// The document holds only age_over_21, and that answers a request for 18
resolveAgeAttestation({ age_over_21: true }, 18)
// → { identifier: 'age_over_21', age: 21, value: true }

// Not being over 65 says nothing about being over 18
resolveAgeAttestation({ age_over_65: false }, 18)
// → undefined
```

Issuing works from the other side. §7.2.5 requires the values to hold at the
MSO's `validFrom`, not at the moment of issuance, so that is what you pass:

```ts
import { ageAt, buildAgeAttestations, readAgeAttestations } from '@m-doc/mdl'

buildAgeAttestations(birthDate, validFrom, [16, 18, 21, 65])
// → { age_over_16: true, age_over_18: true, age_over_21: false, age_over_65: false }

readAgeAttestations(claims)     // every age_over_NN present, ascending
// → [{ identifier: 'age_over_18', age: 18, value: true }, …]

ageAt(birthDate, someDate)      // whole years
```

## Driving privileges

The claim arrives as decoded CBOR — an array of `Map`s. Read it into something
typed:

```ts
import { privilegesFor, readDrivingPrivileges } from '@m-doc/mdl'

readDrivingPrivileges(claims.driving_privileges)
// → [{ vehicleCategoryCode: 'B', issueDate: DateOnly, codes: [{ code: '01', sign: '=', value: '1' }] }]

privilegesFor(claims.driving_privileges, 'B')
```

## Element identifiers and encodings

Every element Table 5 names has one fixed encoding — there is no choosing.

```ts
import { encodingFor, MDL_ELEMENT_ENCODING } from '@m-doc/mdl'

encodingFor('family_name')          // 'tstr'
encodingFor('birth_date')           // 'full-date'
encodingFor('portrait')             // 'bstr'
encodingFor('height')               // 'uint'
encodingFor('driving_privileges')   // 'structure'
encodingFor('issue_date')           // 'tdate-or-full-date' — Table 5 allows either
encodingFor('age_over_65')          // 'bool' — any NN, not only the listed ones
encodingFor('org.example.custom')   // undefined
```

`MDL_ELEMENT_ENCODING` is the map itself, if you would rather iterate it.
`encodingFor` is the one to call, because it also answers for `age_over_NN`,
where NN is open-ended.

```ts
import {
  MDL_DOC_TYPE,               // 'org.iso.18013.5.1.mDL'
  MDL_NAMESPACE,              // 'org.iso.18013.5.1'
  jurisdictionNamespace,      // jurisdictionNamespace('DE') → 'org.iso.18013.5.1.DE'
  MDL_MANDATORY_ELEMENTS,     // Table 5, presence M
  MDL_OPTIONAL_ELEMENTS,      // Table 5, presence O
  parseAgeOverIdentifier,     // 'age_over_18' → 18
  Sex,                        // ISO/IEC 5218
  EYE_COLOURS,
  HAIR_COLOURS,
} from '@m-doc/mdl'
```

The identifier types are exported too — `MdlElementIdentifier`,
`MdlMandatoryElementIdentifier`, `MdlOptionalElementIdentifier`,
`AgeOverIdentifier`, `MdlEncoding`, `EyeColour`, `HairColour`, `SexValue` — so a
typo in an element name is a compile error rather than a claim nobody reads.

## Profile checks

```ts
import { findMissingMandatoryElements, isExpired, isNotYetValid } from '@m-doc/mdl'

findMissingMandatoryElements(claims)   // Table 5 elements the document lacks
isExpired(claims)                      // undefined where expiry_date was not disclosed
isNotYetValid(claims, someDate)
```

`findMissingMandatoryElements` is a finding on a document that was meant to be
complete — one straight from an issuer. A presented mDL is allowed to disclose a
subset; that is the point of selective disclosure.

`isExpired` and `isNotYetValid` return `undefined` rather than `false` when the
date they need was not disclosed, so "we do not know" never reads as "it is
fine".

## Requirements

Node 20.19 or newer. Ships ESM and CJS, with type declarations for both. Depends
only on `@m-doc/core`, and only for its `DateOnly` type.

## License

Apache-2.0.
