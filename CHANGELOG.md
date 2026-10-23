## 1.6.5 - 2026-10-23
- Match Administrative Privilege Exposure terminal account casing to the credential registry when safely matched, falling back to readable graph-label casing.
- Display domain names in lowercase in the exposure table, consistent with Privilege Debug, without changing canonical identifiers or CSV exports.
- Add three synthetic regression tests for case preservation, graph-only fallback, and cross-domain SID mismatch.

## 1.6.4 - 2026-10-23
- Apply CredWeave terminal colors to privilege debug headings, reach counts, targets, membership chains, and Tier 0 evidence.
- Match graph-debug account casing to the imported credential registry when available and collector group casing when available; otherwise normalize all-uppercase graph labels for display.
- Render debug domain names in lowercase while retaining unchanged canonical identities and CSV content.
- Add synthetic regression coverage for ANSI styling, mixed-case identity presentation, and unchanged graph records.

## 1.6.3 - 2026-10-23
- Resolve nested BloodHound collector group membership by SID with cycle protection, including edges supplied across repeated ZIP imports.
- Derive privilege/Tier 0 group labels through effective membership; store the shortest collector membership evidence chain and its source.
- Preserve domain-qualified effective groups when bridging collector memberships to graph `AdminTo` exports.
- Merge repeated graph node classification evidence rather than discarding later Tier 0 indicators.
- Display collector-derived Tier 0 membership paths with `--privilege-debug`. These are local inferences, **not** BloodHound CE security-zone assignments.
- Add seven synthetic regression tests; sanitize pre-existing test and documentation example identifiers.

## 1.6.2
- Decode valid UTF-8 hashcat `$HEX[...]` potfile plaintexts before downstream analysis and rule generation.
- Preserve malformed or non-UTF-8 encodings unchanged.
- Add regression tests for HEX handling, including embedded colons.

# Changelog

## 1.6.1 - 2026-10-01

Initial public release.

CredWeave provides NTLM credential-reuse analysis, enabled/disabled account
context, BloodHound Legacy/CE enrichment, privilege-boundary analysis,
reporting-oriented affected-resource output, potfile correlation, password
statistics, candidate/mask/rule generation, and target-adaptive cracking.

### 1.6.1
- Fixed the missing `Counter` import introduced with adaptive rule statistics.

### 1.6.0
- Added tiered adaptive rule learning.
- Added recurring target-pattern generalization.
- Added conservative adjacent-year hypotheses.

### 1.5.x
- Canonicalized candidate words and combinator tokens.
- Replaced `--password-stats` with `--no-password-stats`.
- Tightened plaintext masking behavior.

### 1.4.x
- Added BloodHound account-status enrichment when available.
- Added explicit BloodHound status/capability warnings.
- Added Tier 0 cracked/uncracked credential reporting.

### Domain aliases (2026-10-23)
- Added repeatable `--domain-alias ALIAS=CANONICAL` to explicitly normalize NTDS embedded domain prefixes (for example `ALIAS.EXAMPLE=CORP.EXAMPLE`).
- Domain labels on `--ntds DOMAIN=PATH` remain strict after alias normalization. Unrecognized embedded domains still raise an error.
- Original account strings remain in the input files; normalized domain-qualified identities are used internally for correlation.
- Added normalization count output and regression tests for mixed-prefix dumps, cross-domain username collisions, invalid aliases, and conflicting NT hashes.

### Administrative exposure reporting improvements
- Export BloodHound SID and credential match method (`SID`, `Domain+Username`, or `None`) for direct AdminTo accounts. SID is a graph identity, not proof of SID-based credential matching.
- Include domain-qualified account details, status, privilege classification, account-domain distribution, cross-domain reuse, and administrative/privileged/Tier Zero account counts in credential exposure CSV.
- Align credential-reuse administrative reach terminal summary using dynamically sized table columns.
- Preserve existing CSV columns and append new metadata; no raw plaintext credentials are exported.

## Effective administrative reach (2026-10-23)
- Traverse graph-export `User -> MemberOf* -> Group -> AdminTo -> Computer` paths, including nested groups and cycle protection.
- Keep direct, inherited, and deduplicated effective target counts distinct. Count overlapping targets once in effective reach.
- Recalculate reused-credential administrative exposure from effective reach.
- Preserve SID-based account matching, domain separation, and aligned ANSI terminal output.
- Extend privilege CSV with direct/inherited/effective targets, granting groups, and Tier Zero systems.
- Distinguish `T0_ACCOUNT` (credential-registry classification) from `T0_ADMIN_ACCESS` (graph target).
- Limitations: only explicit graph-export `MemberOf` and `AdminTo` edges are analyzed; this is not a full BloodHound path engine. Group paths are not individually exported. Effective reach is graph-observed, not proof of successful authentication.
