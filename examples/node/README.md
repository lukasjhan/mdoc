# Examples

Four TypeScript programs, each one runnable and each one about a single step of
the mdoc lifecycle. Read them top to bottom; they are written to be read rather
than imported.

```bash
pnpm install     # from the repository root
cd examples/node

pnpm issue       # sign an mDL
pnpm present     # answer a request with a subset of it
pnpm verify      # check what came back, one named check at a time
pnpm vical       # read a real AAMVA trust list

pnpm all         # all four in order
```

No build step: the workspace packages resolve to their TypeScript sources, and
`tsx` runs them directly.

| File | Shows |
| --- | --- |
| [`src/01-issue.ts`](./src/01-issue.ts) | Building claims with the right CBOR types, deriving `age_over_NN`, signing an MSO, adding a status list entry, reading the result back as CBOR and as JSON |
| [`src/02-present.ts`](./src/02-present.ts) | Session transcripts, an items request, selective disclosure, `intentToRetain`, and the §7.2.5 age resolution |
| [`src/03-verify.ts`](./src/03-verify.ts) | Collecting every verification check rather than throwing on the first, grouped by category, then the profile checks a signature cannot answer |
| [`src/04-vical.ts`](./src/04-vical.ts) | Decoding and verifying a trust list, looking entries up by country, SKI and docType, and handing the certificates to a verifier |

## The setup, kept out of the way

[`src/shared.ts`](./src/shared.ts) holds the parts that are not mdoc-specific —
generating a P-256 key pair, issuing a self-signed certificate, and the
`MdocContext` the library takes its cryptography from. Every example imports it
so that each one stays about the format.

The certificates these examples generate are self-signed and trusted by nobody.
A real issuer's document signer is issued by an IACA, and a real verifier's
trust anchors come from a list like the one `04-vical.ts` reads.

## The VICAL fixture

[`fixtures/aamva-vical.cbor`](./fixtures/aamva-vical.cbor) is a genuine VICAL:
AAMVA's list of US jurisdiction IACAs, fetched on 2026-08-05. It carries 20
entries, is signed with ES256 over a three-certificate chain, and re-encodes to
the bytes it arrived as.

Its `nextUpdate` is a day after its `date`, so it is stale by now — which is
itself worth seeing, since a stale list verifies perfectly well and should still
be refetched.

## Browser

For the same operations with a UI, see
[`examples/playground`](../playground) — decode, issue, present and VICAL tabs,
all client side.
