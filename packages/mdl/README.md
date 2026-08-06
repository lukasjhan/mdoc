<h1 align="center"><b>@m-doc/mdl</b></h1>

<p align="center">
  <a href="https://www.npmjs.com/package/@m-doc/mdl">
    <img src="https://img.shields.io/npm/v/@m-doc/mdl" />
  </a>
</p>

The mDL profile of [ISO/IEC 18013-5:2021](https://www.iso.org/standard/69084.html):
what its element identifiers are, and the handful of rules that are easy to get
wrong when issuing or verifying one.

[`@m-doc/core`](../core) reads and writes the document; this package says what
belongs in it.

## Installation

```bash
npm i @m-doc/mdl
```

## Age attestations

An mDL conveys age without revealing a date of birth, through `age_over_NN`
elements. §7.2.5 defines what a request for one means, and it is not "return
the element with that name":

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
import { buildAgeAttestations } from '@m-doc/mdl'

buildAgeAttestations(birthDate, validFrom, [16, 18, 21, 65])
// → { age_over_16: true, age_over_18: true, age_over_21: false, age_over_65: false }
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

## Identifiers and profile checks

```ts
import {
  MDL_DOC_TYPE,               // 'org.iso.18013.5.1.mDL'
  MDL_NAMESPACE,              // 'org.iso.18013.5.1'
  jurisdictionNamespace,      // jurisdictionNamespace('DE') → 'org.iso.18013.5.1.DE'
  MDL_MANDATORY_ELEMENTS,
  findMissingMandatoryElements,
  isExpired,
  isNotYetValid,
} from '@m-doc/mdl'

findMissingMandatoryElements(claims)   // Table 5 elements the document lacks
isExpired(claims)                      // undefined where expiry_date was not disclosed
```

`findMissingMandatoryElements` is a finding on a document that was meant to be
complete — one straight from an issuer. A presented mDL is allowed to disclose
a subset; that is the point of selective disclosure.

## License

Apache-2.0.
