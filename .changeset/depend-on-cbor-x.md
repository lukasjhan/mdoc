---
"@lukas.j.han/mdoc": minor
---

chore: depend on `cbor-x` instead of vendoring it.

`src/cbor/cbor-x/` held a 2,618-line copy of cbor-x that had been reformatted by `biome check --unsafe`. The copy was verified functionally identical to the upstream `cbor-x@1.6.0` release it was taken from, so the vendoring provided no behavioural difference — only a maintenance cost and a version freeze. It now resolves to `cbor-x@^1.6.5` as a regular dependency, matching what `@owf/cose` does upstream.

The original motivation for vendoring — React Native resolving cbor-x to the Node build — no longer applies: React Native supports package `exports`, so it selects the pure-JS entry, as do browser bundlers. Only Node resolves the `node` condition, where the optional `cbor-extract` accelerator is used when present and falls back to pure JS otherwise. Native and pure-JS paths were checked to produce identical bytes.

Moving from the pinned 1.6.0 to 1.6.5 picks up two upstream fixes that affect CBOR handling:

- **Malformed UTF-8 is no longer silently accepted.** Overlong encodings (`c0 80`, previously decoded to `U+0000`), lone surrogates, and truncated sequences now decode to `U+FFFD`. Since namespace names, element identifiers and docTypes are attacker-controlled strings, the previous behaviour allowed an overlong-encoding bypass of any downstream string comparison.
- **Negative integers in `[-2^32, -2^31)` encode as CBOR negative integers rather than float64.** `-2147483649` previously emitted `fb c1e0000000200000` instead of `3a 80000000`, breaking deterministic encoding and interoperability with strict parsers.

No public API change. Bundled output drops from 176 kB to 109 kB (gzip 34.3 kB → 19.6 kB) as cbor-x is now external.
