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
