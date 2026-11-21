# DSSE vs. Metablock: The Two Signature-Wrapper Contracts in `in-toto-golang`

**Status:** source-analysis report. Every claim below is tagged with the evidence that
supports it:

| Tag | Meaning |
| --- | --- |
| **[code]** | Follows directly from repository source, cited by `file:line`. |
| **[lib]** | Follows from the vendored `go-securesystemslib@v0.10.0` source (`dsse/`, `cjson/`). |
| **[test]** | Exercised by an existing test in this repository. |
| **[probe]** | Verified experimentally with a temporary Go test against the repo and its fixtures (probe code was removed afterwards; commands in Appendix A). |
| **[unproven]** | Reasoned from source but not demonstrated by code paths exercised in tests; treat as a hypothesis to confirm. |

All citations are relative to the repository root at commit `d73848d`.

---

## 1. Scope and method

The library exposes one verification contract (`in_toto.Metadata`, `in_toto/model.go:690-697`)
implemented by two wrappers:

* `*Metablock` — the legacy in-toto wrapper: `{"signed": <link|layout>, "signatures":[...]}`.
* `*Envelope` — the DSSE wrapper: `{"payloadType": ..., "payload": <b64>, "signatures":[...]}`.

Downstream code (`InTotoVerify`, `LoadLinksForLayout`, `VerifyLinkSignatureThesholds`,
`RunInspections`, `GetSummaryLink`) is written against `Metadata` and is therefore
wrapper-agnostic on paper. This report compares the two implementations of that shared
interface on four contract dimensions (payload binding, signer identity, step context,
replay protection) and then on three engineering dimensions (verification order, error
propagation, migration compatibility).

**Important framing.** The security-relevant differences are *not* in the crypto. Both
wrappers delegate to the same `signerverifier` implementations and the same three key
types (`in_toto/envelope.go:142-151`). The differences are in **what bytes are signed**,
**what the signature is keyed by**, **what is validated before and after verification**,
and **what the API lets a caller do without realising it**.

---

## 2. At a glance

| Property | Metablock | DSSE Envelope |
| --- | --- | --- |
| Signed bytes | `cjson` canonical encoding of the **re-serialised struct** (`model.go:884-886`) | **Raw payload bytes** as produced by the signer, wrapped in PAE `DSSEv1 <len> <type> <len> <body>` (`envelope.go:89-94`, library `dsse/sign.go:60-85`) |
| Payload type binding | none | PAE binds `payloadType` cryptographically (`dsse/envelope.go:44-48`) |
| Type tag enforced at verify time | n/a (`_type` checked only at load, `util.go:161-189`) | **No** — checked only in `LoadMetadata` (`model.go:720-722`); `VerifySignature` never checks it **[probe]** |
| Signature encoding | lowercase **hex** (`model.go:919`, `model.go:993`) | **base64** (std or URL-safe) (`dsse/envelope.go:54-64`, `dsse/sign.go:80`) |
| Signature `keyid` role | **selector**: required to find the signature (`model.go:904`) | **hint**: may be empty or stale; verification falls back to `SHA256KeyID(public)` (`dsse/verify.go:58-77`) **[probe]** |
| Certificates in signatures | supported: `Signature.Certificate` (`model.go:290-294, 994`) | **impossible**: `dsse.Signature` has no cert field (`dsse/envelope.go:35-38`); `Sigs()` drops nothing because there is nothing to drop (`envelope.go:103-112`) **[lib][probe]** |
| Adding a signature | **appends** (`model.go:991-995`) | **replaces the entire signature set** (`envelope.go:94-99` + `dsse/sign.go:60-64`) **[probe]** |
| `SetPayload` | n/a (direct field write) | canonicalises and **clears all signatures** (`envelope.go:44-57`) **[code]** |
| Structural validator | `ValidateMetablock` (`model.go:947-967`) | **none** |
| Anti-replay material | none | none (PAE domain separation only) |

---

## 3. Contract dimension 1 — payload binding

### 3.1 The two signable representations

**Metablock** signs `cjson.EncodeCanonical(mb.Signed)` (`model.go:884-886`), and the
verifier recomputes the same encoding from the *parsed struct* (`model.go:914`) before
calling `verifier.Verify` (`model.go:924`). The verifier therefore never hashes the raw
`"signed"` bytes on disk; it hashes the re-encoding of what those bytes parsed into.

(In-toto-native producers sign `cjson` over in-memory structs, so their signatures match
exactly. The two diverge for any input the struct round-trip does not preserve — §3.2a.)

**DSSE** signs `PAE(payloadType, base64_decode(payload))` (`envelope.go:89-94` →
`dsse/sign.go:66`). The verifier decodes the *same* payload string and reconstructs PAE
(`dsse/verify.go:36-41`). The payload is parsed separately into a Link/Layout for
downstream use (`envelope.go:30-39`) but *that parse does not participate in
verification*.

### 3.2 Consequences of the difference

**(a) Metablock loses information between signature and struct; DSSE does not.**
`loadPayload` decodes JSON into Go structs (`util.go:155-190`), so `byproducts` and
`environment` values become `float64`/`interface{}` and numbers are re-emitted by
`json.Marshal` before `cjson` sees them (`cjson/canonicaljson.go:116-149`). **[probe]**
Demonstrated:

```
input : {"byproducts":{"return-value":1.0,"big":9007199254740993}, ...}
recano: {"byproducts":{"big":9007199254740992,"return-value":1}, ...}
identical: false
```

A documented consequence: any two on-disk documents that parse to the same struct are
interchangeable for Metablock verification. That is acceptable for integrity of *semantic*
content, but it means Metablock cannot authenticate a byte-level artefact, and it
normalises (and, above 2^53, corrupts) numeric `byproducts`. Digest maps are `string →
string`, so artifact hashes are unaffected.

**(b) DSSE preserves payload bytes exactly.** **[probe]** A prettified, non-canonical
payload (indentation, key order, `1.0`) signed with `dsse` verifies unchanged through
`Envelope.VerifySignature`; the Metablock path would instead verify over a 118-byte
canonical form of a 150-byte document that was never signed in that form.

**(c) The two formats are not signature-convertible.** Because Metablock signs
`cjson(payload)` and DSSE signs `PAE(type, payload)`, a Metablock signature can never be
reused as a DSSE signature or vice versa. Migration between wrappers **requires every
functionary to re-sign** — this is the single most important migration constraint and is
not documented anywhere in the repository. **[code][lib]**

**(d) Neither wrapper binds:**
* the effective layout after `SubstituteParameters` (substitution runs *after* signature
  verification, `verifylib.go:916` then `verifylib.go:937`),
* the step name (see §5),
* any timestamp, nonce, or link-directory identity (see §6).

**(e) DSSE's type binding is real but unenforced by in-toto.** PAE makes
`payloadType` part of the signed pre-image, so an attacker cannot relabel a document
without breaking the signature. However `Envelope.VerifySignature` never compares
`payloadType` to `PayloadType`; the only check is in `LoadMetadata`
(`model.go:720-722`). **[probe]** An envelope with `payloadType:"application/evil+json"`
that is cryptographically valid under Alice's key returns `nil` from
`VerifySignature`. The residual risk is cross-protocol replay: a signature legitimately
produced for a different attestation type over the same bytes would be accepted by
in-toto as long as the embedded document parses as a Link/Layout.

---

## 4. Contract dimension 2 — signer identity

### 4.1 Identity is a selector in Metablock, a hint in DSSE

`Metablock.VerifySignature` performs `GetSignatureForKeyID(key.KeyID)` **first**
(`model.go:904`); if no signature carries that keyid, verification fails before any crypto
runs. The keyid is therefore load-bearing: it decides *which* signature is checked, and
only that one signature is ever decoded (`model.go:919`) or verified.

`Envelope.VerifySignature` constructs a `dsse.EnvelopeVerifier` with **threshold 1** and
exactly one verifier (`envelope.go:69-74`) and hands the *whole* signature list to the
library. The library:

* skips a signature only when both keyids are non-empty and differ
  (`dsse/verify.go:70-72`),
* falls back to `SHA256KeyID(v.Public())` when the provider's keyid is empty
  (`dsse/verify.go:60-68`),
* tries every signature against the provider (`dsse/verify.go:48-95`).

**[probe]** Concretely, taking the `demo.dsse.layout` fixture and blanking the signature's
`keyid`:

```
DSSE VerifySignature with emptied keyid: <nil>
```

The same blanking of the *key's* `KeyID` fails in both wrappers but with different error
classes:

```
Metablock: no signature found for key ''
DSSE     : accepted signatures do not match threshold, Found: 0, Expected 1
```

So **a DSSE envelope's `keyid` field is not part of the trust decision**; only the crypto
and the verifier's own key are. This is spec-correct DSSE behaviour, but it is a contract
difference that in-toto code elsewhere does not account for. `LoadLinksForLayout`
(`verifylib.go:669-677`) matches the file-name keyid prefix against `sig.KeyID` and keys
the step map by `sig.KeyID`; a keyid-less DSSE link therefore matches no file name and is
**silently dropped**. **[probe]** Writing a valid DSSE link with an emptied `keyid` as
`foo.2f89b927.link` and calling `LoadLinksForLayout`: the step map contained only the two
pre-existing `foo.*.link` fixtures and **no empty-keyid entry** — the DSSE link vanished
with `err == nil` (threshold still met by the other fixtures). In a real chain the loss
surfaces as a threshold shortfall, not as an identity problem.

### 4.2 Certificate-backed functionaries work for one wrapper only

`VerifyLinkSignatureThesholds` has a second, independent path for functionaries not listed
in `step.PubKeys`: it reads the certificate embedded in the signature
(`verifylib.go:580-590`), checks it against the step's certificate constraints and the
layout's root/intermediate CAs (`verifylib.go:593`), and verifies with that certificate as
the key (`verifylib.go:599`). The whole feature depends on
`Signature.Certificate` (`model.go:290-294, 994`).

**`dsse.Signature` has no certificate field** (`dsse/envelope.go:35-38`); `Envelope.Sigs()`
constructs `in_toto.Signature` with only `KeyID` and `Sig` (`envelope.go:103-112`).
**[probe]** On the real fixture `test/data/package-dsse.2f89b927.link`, the reconstructed
signature carries `Certificate` length 0 and `GetCertificate()` returns
`Signature has empty Certificate`. Consequently:

> Any step that relies on `rootcas` / `intermediatecas` / certificate constraints is
> **unsatisfiable with DSSE links**, and the failure is reported as a generic threshold
> shortfall, not as "certificates are unsupported".

A DSSE producer *can* still sign with a certificate PEM as key material — the cert is just
not carried, so the verifier has no way to obtain it.

### 4.3 Multi-signature semantics diverge sharply

This is the highest-impact API asymmetry found. **[probe]** on real fixtures:

```
DSSE sigs before: 1  keyids=[70ca5750...]
DSSE after carol: 1  keyids=[be6371bc...]      <- original signature destroyed
DSSE after alice: 1  keyids=[70ca5750...]      <- carol's signature destroyed

Metablock sigs before: 1  keyids=[70ca5750...]
Metablock after carol+alice: 3  keyids=[70ca5750..., be6371bc..., 70ca5750...]
```

`Envelope.Sign` builds a *new* envelope from the payload and replaces `e.envelope`
(`envelope.go:94-99`); `dsse.SignPayload` always starts from an empty signature slice
(`dsse/sign.go:60-64`). `Metablock.Sign` appends (`model.go:991-995`). Practical
consequences:

* `in-toto-sign --file x --key alice` followed by `--key bob` on a DSSE layout leaves a
  layout signed **only by bob** — silent loss of co-signatures. `cmd/sign.go:63-91` has no
  guard and there are no CLI tests. **[code][unproven in tests]**
* Co-signing the same file twice with the same key produces a duplicate Metablock signature
  (see the 3-entry list above) rather than an error or replacement.
* `SetPayload` has the same destructive effect on an envelope that already has signatures
  (`envelope.go:44-57`), which is why `InTotoRecordStop` deliberately re-signs from
  scratch (`runlib.go:449-470`).

The existing DSSE tests never sign twice: every DSSE fixture in `test/data/` carries
**exactly one** signature, and `Threshold` is `1` for every step in both DSSE layouts
(`demo.dsse.layout`, `dsse-only.root.layout`). **Multi-signature DSSE threshold
verification is untested.** **[test][probe inspection of fixtures]**

---

## 5. Contract dimension 3 — step context

Neither wrapper provides a cryptographic step binding. The step a link belongs to is
established **outside** the signed document, by the file name:

* `LoadLinksForLayout` globs `<step>.<8-hex>.link` (`verifylib.go:657`, formats at
  `model.go:407,417`) and requires the 8-character prefix to equal the first 8 hex chars
  of a signature `keyid` (`verifylib.go:669-677`).
* `VerifyLinkSignatureThesholds` iterates `layout.Steps` and matches `step.PubKeys`
  against the **map key** (the full signature keyid), then calls
  `linkEnv.VerifySignature(verifierKey)` (`verifylib.go:564-575`).

The signed `Link.Name` is never compared to the step name. **[probe]** A link whose payload
is `"name":"write-code"` was placed under step `"foo"` and reached the threshold:

```
link payload name="write-code" indexed as step "foo"; verified=1 err=<nil>
```

So a link validly signed for step *A* can be presented as evidence for step *B* whenever
the two steps share an authorized functionary. The 8-char filename prefix is *not* the
security check (the full-keyid equality at `verifylib.go:566` is), so no prefix-collision
bypass was found — but the loader dependency is real and DSSE-specific only in that a
keyid-less DSSE envelope cannot satisfy it at all (§4.1).

Sublayout recursion reinforces this: whether a piece of metadata is treated as a sublayout
is decided by `metadata.GetPayload().(Layout)` (`verifylib.go:785`), and sublayout link
directories are derived from `stepName` + `keyID` (`verifylib.go:789-791`) — again
out-of-band naming, identical for both wrappers.

---

## 6. Contract dimension 4 — replay protection

**Neither wrapper implements any replay defence.** Grep-level facts, both formats:

* No nonce, timestamp, sequence, or link-directory identity in `Signature`
  (`model.go:290-294`) or `dsse.Signature` (`dsse/envelope.go:35-38`).
* Links have no expiry; only layouts do (`VerifyLayoutExpiration`,
  `verifylib.go:693-704`).
* Re-use of a previously valid link is only indirectly constrained by artifact rules and
  by `ReduceStepsMetadata`'s requirement that all links for a step agree on
  `Materials`/`Products` (`verifylib.go:430-438`).

DSSE adds exactly one replay-relevant property: PAE domain separation by `payloadType`
(§3.2e). It is only as strong as the verifier's willingness to check the type, and in-toto
does not (`model.go:720` is load-time only; **[probe]** a foreign type verifies). So DSSE's
replay posture in this codebase is *marginally* better than Metablock's in theory and
**equal in practice**.

No test in the repository attempts a stale-link replay. **[unproven]**

---

## 7. Verification order

### 7.1 Per-wrapper order

**Metablock** (`model.go:903-930`):

1. `GetSignatureForKeyID(key.KeyID)` — identity lookup
2. `getSignerVerifierFromKey` — key type/scheme construction
3. `GetSignableRepresentation` — canonicalisation
4. `hex.DecodeString(sig.Sig)`
5. `verifier.Verify`

**DSSE** (`envelope.go:63-76` → `dsse/verify.go:26-107`):

1. `getSignerVerifierFromKey` + `NewEnvelopeVerifier` — key construction (threshold 1)
2. reject `nil` / empty signature list (`ErrNoSignature`)
3. `DecodeB64Payload` → PAE
4. for each signature: **base64-decode, then keyid match, then crypto** — a failure to
   base64-decode any signature aborts the whole call
5. threshold check (`usedKeyids < 1`)

Two order facts matter operationally:

* **Metablock masks key errors when the signature is absent; DSSE masks absent signatures
  when the key is invalid.** Both fail closed; only the diagnostic differs.
* **DSSE is fail-closed over the whole signature set; Metablock is fail-open over unrelated
  entries.** **[probe]**

```
DSSE with malformed extra sig ("!!!not-base64!!!"): unable to base64 decode payload (is payload in the right format?)
Metablock with non-hex extra sig ("zzzz"):          <nil>
```

The DSSE error text is also misleading: the malformed object is a *signature*, not the
payload.

### 7.2 Shared pipeline order (`InTotoVerify`, `verifylib.go:911-1006`)

Both wrappers run through the identical sequence:

1. layout signatures (`:916`) — **AND** over every supplied key (`verifylib.go:713-726`)
2. `useDSSE` inferred from the **layout's** concrete type (`:920-923`)
3. layout payload type assertion (`:926-929`)
4. layout expiry (`:932`)
5. parameter substitution (`:937`) — *after* signing, therefore unsigned
6. certificate pools (`:942`)
7. link loading (`:948`) — silent-skip semantics, see §8
8. link signature thresholds (`:954`)
9. sublayout recursion (`:961`)
10. command alignment, **warn only** (`:968`)
11. `ReduceStepsMetadata`, artifact rules, inspections, inspection rules, summary

Only step 2 differs between wrappers, and it is derived from the **layout**, not from
individual links. Mixed chains are therefore accepted and tested (DSSE layout + Metablock
links, `verifylib_test.go:47-66`; all-DSSE chain, `verifylib_test.go:73-92`). The summary
link and inspection links inherit the layout's wrapper (`verifylib.go:986, 1002`;
`runlib.go:352-370`).

`InTotoVerifyWithDirectory` (`verifylib.go:1014-1147`) duplicates the entire sequence. Any
wrapper rule added to one must be added to the other.

---

## 8. Error propagation

| Situation | Metablock | DSSE |
| --- | --- | --- |
| Missing signature for key | `no signature found for key 'X'` (`model.go:940`) | `accepted signatures do not match threshold, Found: 0, Expected 1` (**[probe]**) |
| Unsupported key type | `ErrUnsupportedKeyType` (`envelope.go` shared helper) | same error, reached *before* signature lookup |
| Bad signature | `ErrSignatureVerificationFailed` (library) | same |
| Malformed unrelated signature | ignored (**[probe]**) | aborts whole verification, mislabelled as payload b64 error (**[probe]**) |
| Layout with unknown `payloadType` | n/a | `ErrInvalidPayloadType`, **only from `LoadMetadata`** (`model.go:720-722`) |
| Certificate functionary | tries cert path | cert path always fails with `Signature has empty Certificate` (**[probe]**) |

Two pipeline-level masking behaviours affect **both** wrappers and are worth calling out
because they make migration failures indistinguishable from missing evidence:

* `LoadLinksForLayout` **silently `continue`s** on any load error (`verifylib.go:663-666`).
  A directory half-migrated to DSSE with the wrong `payloadType` produces
  `step 'x' requires '1' link metadata file(s), found '0'` (`verifylib.go:679-682`) rather
  than `unknown payload type`. **[code]**
* `linkEnv.VerifySignature(verifierKey)`'s error in the pubkey branch is discarded — the
  `if err := linkEnv.VerifySignature(...); err == nil` at `verifylib.go:568` keeps no
  error — and only the last cert-branch error survives in `stepErr`
  (`verifylib.go:582-602`), which is appended to the aggregate threshold message
  (`verifylib.go:613-618`). **[code]**

Additionally, `ValidateMetablock` (`model.go:947-967`) has **no DSSE counterpart**, and it
is not invoked by `InTotoVerify` for either format. DSSE payload typing is instead enforced
at parse time by `loadPayload` (`util.go:161-189`: required fields + `DisallowUnknownFields`),
so the gap is mostly at the public-API level (library consumers can validate a Metablock but
not an Envelope), not in the CLI verify path.

---

## 9. Migration and compatibility

### 9.1 What works

* **Auto-detection by key presence.** `LoadMetadata` routes on `payloadType`
  (`model.go:710`); otherwise it expects `signed`+`signatures` (`model.go:732`). Both
  wrappers round-trip through `Dump`/`LoadMetadata` (`envelope_test.go:126-164`,
  `model_test.go:168`).
* **Mixed chains.** Layout and links may use different wrappers; `run`/`record` can emit
  DSSE (`--use-dsse`, `cmd/run.go:153-156`, `cmd/record.go:131-134`) while
  `in-toto-verify` consumes either.
* **Key material is shared.** `getSignerVerifierFromKey` (`envelope.go:139-152`) maps
  `in_toto.Key` to the same RSA-PSS / Ed25519 / ECDSA verifiers used by Metablock, and the
  keyid written on DSSE signing is the same `key.KeyID` (`dsse/sign.go:73-81`), which is
  the in-toto canonical-map hash (`keylib.go:94-115`).

### 9.2 What breaks or surprises

1. **Re-signing is mandatory.** No signature transcoding is possible (§3.2c). A threshold
   layout move to DSSE invalidates every collected signature.
2. **Co-signing is destructive** on DSSE (§4.3).
3. **Certificate-based functionaries are lost** (§4.2).
4. **Signature encoding changes** from hex to base64. `Envelope.Sigs()`
   (`envelope.go:103-112`) returns `in_toto.Signature` values whose `Sig` is base64,
   violating the invariant enforced for Metablock by `validateSignature`
   (`model.go:312-320`). Any consumer that hex-decodes `Metadata.Sigs()` breaks.
   Fixtures confirm the split: `package-dsse.2f89b927.link` sig is base64;
   `package.d3ffd108.link` sig is hex.
5. **Keyid fallback** may reject envelopes whose keyids were produced by other tools (ssh
   fingerprint style) even though the crypto is valid (§4.1).
6. **Ambiguous documents are accepted.** Routing is decided solely by the presence of the
   `payloadType` key (`model.go:710`). **[probe]** Splicing a decoy `"signed"` object into
   a valid DSSE link still loads as `*in_toto.Envelope` with the *real* DSSE payload
   (`name="package-dsse"`); the decoy is ignored without error. The reverse case
   (`payloadType` present but no `payload`/`signatures`, plus a valid `signed`) fails with
   `in-toto metadata envelope requires 'payload' and 'signatures' parts` — the valid
   Metablock half is never considered. A document can thus carry two contradictory payloads
   and verify against whichever one the reader's dispatcher picks.
7. **Unsigned outputs cannot be reloaded.** Both wrappers serialise an empty signature set
   as `"signatures": null`, and both loaders reject `null`
   (`model.go:712`, `model.go:732`). **[probe]** `GetSummaryLink` returns an **unsigned**
   envelope/Metablock (`verifylib.go:762-772`), so dumping a summary produces a file that
   cannot be loaded. `in-toto-verify` discards the summary, so the CLI is unaffected
   (`cmd/verify.go:110-114`).
8. **Robustness asymmetry.** `(&Envelope{}).Sign` panics on a nil inner envelope
   (`envelope.go:89`). **[probe]** `(&Metablock{}).Sign` instead returns `nil`, appends a
   signature over the literal `null` (canonical encoding of a nil `Signed`), and emits an
   unloadable file — quieter, but equally wrong. **[probe]**

---

## 10. Security boundaries

### 10.1 What each wrapper actually guarantees

| Guarantee | Metablock | DSSE |
| --- | --- | --- |
| Integrity of the parsed Link/Layout semantics | yes | yes |
| Integrity of the payload **bytes** | **no** (re-canonicalised) | yes |
| Domain separation between in-toto and other payload types | no | **cryptographic, but not enforced by in-toto** |
| Signature bound to a specific signer keyid | yes (keyid selects) | **no** (keyid is a hint) |
| Signatures bound to a certificate identity | yes | **no** (structurally impossible) |
| Signature bound to a step name / step instance | no | no |
| Protection against link replay | no | no |
| Protection against stale layouts | layout `expires` only | layout `expires` only |
| Any protection for post-substitution layout values | no | no |

### 10.2 Explicit non-guarantees

* A DSSE envelope verifies regardless of its `payloadType` unless it went through
  `LoadMetadata` (§3.2e).
* A Metablock signature says nothing about the whitespace, key order, or numeric spelling
  of the document it was found in (§3.2a).
* A valid signature over `Link.Name = "write-code"` can satisfy step `foo` (§5).
* Certificates attached to Metablock signatures are **not** validated during
  `VerifySignature`; trust is decided by the caller via
  `Step.CheckCertConstraints` (`verifylib.go:593`).
* `VerifyStepCommandAlignment` is advisory and prints to stdout (`verifylib.go:451-478`);
  it is not a verification gate.

---

## 11. Recommendations

Ordered by impact/effort. Each names the touch point.

1. **Enforce `payloadType` at verification time.** Give `Envelope.VerifySignature` an
   expected type (or check `e.envelope.PayloadType == PayloadType` inside it,
   `in_toto/envelope.go:63-76`) so callers cannot verify metadata the loader would have
   rejected. Add a regression test asserting a foreign-type envelope fails.
2. **Fix or explicitly forbid DSSE co-signing.** Either merge signatures instead of
   replacing (`in_toto/envelope.go:78-101`) or add `SignAppend`/`SignReplace` and make
   `cmd/sign.go` require an explicit `--replace` for DSSE. Add a two-functionary DSSE
   threshold fixture — none exists today.
3. **Fail loudly when a certificate-constrained step meets a DSSE link.** In
   `VerifyLinkSignatureThesholds` (`verifylib.go:577-606`), if the metadata is an
   `*Envelope` and the step has `CertificateConstraints`, return a distinct
   "certificate-backed functionaries are unsupported for DSSE metadata" error instead of
   `Signature has empty Certificate`.
4. **Bind the step name.** Compare `link.Name` to `step.Name` (warn or error) in
   `VerifyLinkSignatureThesholds`, or add the step name to the signed payload. Cover both
   wrappers with the probe from §5 as a test.
5. **Stop swallowing load errors in `LoadLinksForLayout`.** Collect and report load
   failures (`verifylib.go:663-666`) so `ErrInvalidPayloadType` and parse errors surface.
   Also fix the discarded error at `verifylib.go:568` and the last-error-wins behaviour at
   `verifylib.go:582-618`.
6. **Fix the `isAuthorizedSignature` state leak.** It is declared outside the per-link loop
   (`verifylib.go:563`) and never reset, so once *any* link in a step succeeds via the
   pubkey path, every later link skips the certificate fallback (`verifylib.go:579`). Since
   `linksPerStep` is a map, the outcome is **iteration-order dependent** for steps that mix
   pubkey-authorized and certificate-authorized functionaries. **[unproven]** — the code
   path is unambiguous, but no test builds such a step.
7. **Normalise signature encodings at the `Metadata` boundary.** Have `Envelope.Sigs()`
   expose hex (decoding base64) or add an explicit encoding discriminator, so
   `Metadata.Sigs()` consumers do not hex-decode base64. Add a test that `Sigs()` output
   satisfies `validateSignature`.
8. **Reject ambiguous metadata.** In `LoadMetadata` (`model.go:699-749`), error if both
   `signed` and `payloadType`/`payload` are present, rather than silently preferring DSSE.
9. **Add `ValidateEnvelope`.** Mirror `ValidateMetablock` (`model.go:947-967`): payload
   type, Link/Layout validation, and signature-format checks. Optionally wire both
   validators into the verify entry points.
10. **Handle unsigned metadata.** Emit `"signatures": []` rather than `null` in
    `Envelope.Dump`/`Metablock.Dump` so summaries are reloadable, or reject dumping an
    unsigned object. Also guard `Envelope.Sign` against a nil inner envelope
    (`in_toto/envelope.go:89`) and reject signing a zero-value `Metablock`.
11. **Factor the pipeline.** `InTotoVerify` (`verifylib.go:911`) and
    `InTotoVerifyWithDirectory` (`verifylib.go:1014`) duplicate the order in §7.2; any
    wrapper rule must currently be written twice.
12. **Document the non-convertibility.** Add a migration note stating that switching
    wrappers requires re-signing by every functionary, that DSSE signatures are base64 and
    carry no certificates, and that `--use-dsse` output cannot be verified against
    certificate-constrained steps.

---

## 12. Not established by code or tests

These are deliberately flagged so they are not mistaken for findings:

* **[unproven]** The `isAuthorizedSignature` order-dependence (§11.6) — source-derived
  only; no fixture builds a key-authorized link and a cert-authorized link for the same
  step.
* **[unproven]** Real-world impact of Metablock numeric re-canonicalisation — no fixture
  uses `byproducts` numbers outside `{return-value: 0}`; interoperability with other
  in-toto implementations is untested here.
* **[unproven]** `in-toto-sign` destructive re-signing — `cmd/` has **no tests at all**;
  the behaviour is proven only at the `Envelope.Sign` level (§4.3).
* **[unproven]** Actual stale-link replay — no test constructs a replayed-but-valid link.
* **[unproven]** DSSE threshold verification with >1 signature — every DSSE fixture has
  exactly one signature and every DSSE step has `threshold: 1`.
* **[unproven]** `InTotoVerify` ever calling `ValidateMetablock` — it does not; the
  validator's guarantees apply only to direct library callers.
* **[unproven]** Cross-implementation fixture compatibility (Python `in-toto`, `in-toto`
  attestation libraries) — no such fixture exists in `test/data/`.

---

## Appendix A — Reproducing the probes

The probes were temporary `_test.go` files in `in_toto/`, run with:

```sh
go test ./in_toto/ -run 'TestZZProbe' -count=1 -v
```

Fixtures used: `demo.dsse.layout` (DSSE layout signed by Alice, keyid
`70ca5750…`), `demo.layout` (same layout, Metablock), `package-dsse.2f89b927.link` and
`package.d3ffd108.link` (the same link in both wrappers), `write-code.b7d643de.link`,
`dsse-only.root.layout`, `alice`, `carol`.

Representative probe outputs (verbatim):

```
DSSE sigs before: 1 keyids=[70ca5750c2eda80b18f41f4ec5f92146789b5d68dd09577be422a0159bd13680]
DSSE after carol: 1 keyids=[be6371bc627318218191ce0780fd3183cce6c36da02938a477d2e4dfae1804a6]
DSSE after alice: 1 keyids=[70ca5750c2eda80b18f41f4ec5f92146789b5d68dd09577be422a0159bd13680]
Metablock after carol+alice: 3 keyids=[70ca5750…, be6371bc…, 70ca5750…]

VerifySignature over foreign payloadType "application/evil+json": <nil>
DSSE VerifySignature with emptied keyid: <nil>
DSSE with malformed extra sig: unable to base64 decode payload (is payload in the right format?)
Metablock with non-hex extra sig: <nil>
link payload name="write-code" indexed as step "foo"; verified=1 err=<nil>
DSSE signature carried cert len=0; GetCertificate: Signature has empty Certificate
keyid-less DSSE link dropped by LoadLinksForLayout: loaded step entries had no empty keyid, err=<nil>
ambiguous doc -> *in_toto.Envelope, payload name="package-dsse" (decoy ignored=true)
(&Metablock{}).Sign returned: <nil>; sigs=1
unsigned envelope JSON: {… "signatures": null}; reload: in-toto metadata envelope requires 'payload' and 'signatures' parts
(&Envelope{}).Sign panic: runtime error: invalid memory address or nil pointer dereference
input : {"byproducts":{"return-value":1.0,"big":9007199254740993}, …}
recano: {"byproducts":{"big":9007199254740992,"return-value":1}, …}
```

## Appendix B — Existing test coverage of the wrappers

| Area | Test | Lines |
| --- | --- | --- |
| Envelope set/get/overwrite payload | `TestEnvelopeSetPayload`, `TestEnvelopeGetPayload` | `envelope_test.go:10-124` |
| Envelope dump/load round-trip | `TestEnvelopeDump` | `envelope_test.go:126-164` |
| Envelope signature verify (success/fail/bad key) | `TestEnvelopeVerifySignature` | `envelope_test.go:166-201` |
| Envelope sign (incl. bad key, bad payload) | `TestEnvelopeSign` | `envelope_test.go:203-242` |
| Loader routing + DSSE rejections | `TestLoadMetadata` | `model_test.go:1641-1755`, DSSE cases `:1707-1709` |
| DSSE run / record start / record stop | `TestInTotoRun`, `TestInTotoRecord` | `runlib_test.go:399-509`, `runlib_test.go:549-665` |
| DSSE layout + Metablock links | `TestInTotoVerifyPass/"DSSE layout"` | `verifylib_test.go:47-71` |
| All-DSSE chain | `TestInTotoVerifyPass/"verifying with only DSSE metadata"` | `verifylib_test.go:73-94` |
| Certificate path | only `CheckCertConstraints` / `LoadLayoutCertificates` units | `model_test.go:1579`, `verifylib_test.go:1111` |
| CLI | none | `cmd/` has no `_test.go` |

Not covered: multi-signature DSSE, DSSE + certificate functionaries, DSSE threshold > 1,
step-name binding, replay, `ValidateEnvelope` (does not exist), mixed/ambiguous metadata
documents.
