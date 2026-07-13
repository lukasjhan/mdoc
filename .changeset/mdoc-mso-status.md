---
"@lukas.j.han/mdoc": minor
---

feat: support the MobileSecurityObject `status` element (IETF Token Status List).

The MSO can now carry a `status` reference so mdoc credentials participate in revocation the same way SD-JWT VC does. `Issuer.sign` / `IssuerSignedBuilder.sign` accept an optional `status`, e.g. `status: { statusList: { idx, uri } }`, which is embedded as `status.status_list = { idx, uri }` in the signed MSO. On the read side, `MobileSecurityObject.status` (a new `Status` model exposing `statusList: StatusListInfo`) is parsed back, so a verifier can resolve the referenced `statuslist+jwt`. Non-`status_list` members (e.g. `identifier_list`) are preserved across a decode/encode round-trip. Fully backward compatible — the field is omitted when no status is provided.
