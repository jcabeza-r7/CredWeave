# CredWeave

**Credential Relationship Analysis for Active Directory**

CredWeave turns credential dumps into relationship-focused analysis that is useful both during an engagement and when writing the report. It correlates recovered NT/LM credential material with account state and privilege context from BloodHound, enum4linux-ng, and analyst-supplied privileged-account lists.

The goal is not merely to answer *which hashes repeat?* CredWeave tries to answer the questions that matter after credential material has been recovered:

- Which enabled accounts share credentials?
- Does a privileged or Tier 0 account share credential material with a lower-privileged account?
- Does a likely standard/admin account pair use the same password?
- Are enabled accounts reusing credentials from disabled accounts?
- Which accounts have empty passwords or stored LM hashes?
- Which hashes have already been cracked?
- What changed between two credential dumps?
- Which relationships belong in the affected-resources section of a finding?

CredWeave masks hashes by default and separates high-signal relationships from bulk reuse so terminal output remains screenshot-friendly.

## Requirements

- Python 3
- No third-party Python packages required

Optional enrichment inputs:

- BloodHound collector ZIP, directory, or JSON
- enum4linux-ng JSON
- newline-separated privileged-account lists
- hashcat potfile

## Quick Start

Basic analysis:

```bash
python3 credweave.py ntdsdump.txt
```

With BloodHound enrichment:

```bash
python3 credweave.py ntdsdump.txt \
  --bloodhound bloodhound.zip
```

A more complete engagement run:

```bash
python3 credweave.py ntdsdump.txt \
  --bloodhound bloodhound.zip \
  --enum4linux enum.json \
  -a privileged.txt \
  --potfile ~/.local/share/hashcat/hashcat.potfile \
  --crack-out ntlm-uncracked.txt \
  --lm-crack-out lm.txt \
  --lm \
  --report-dir ./credweave-report
```

BloodHound, enum4linux-ng, and `--admins-file` inputs are repeatable.

## Input Format

The primary input is a secretsdump-style credential dump:

```text
user:rid:lmhash:nthash
```

CredWeave also tolerates additional trailing metadata commonly present in real dumps, including account-status information.

Machine accounts ending in `$` are retained for analysis/export but excluded from human credential-reuse statistics.

## BloodHound Enrichment

```bash
python3 credweave.py ntdsdump.txt \
  --bloodhound bloodhound.zip
```

CredWeave accepts a BloodHound collector ZIP, directory, or JSON and uses group membership and user metadata to enrich privilege and account-state analysis.

This enables higher-signal relationships such as:

```text
=== Privilege Boundary Credential Reuse ===
[!] Credential shared across a privilege boundary
    Privileged: admeggsample [Tier 0]
    Other: eggsample
```

## enum4linux-ng Enrichment

```bash
python3 credweave.py ntdsdump.txt \
  --enum4linux enum.json
```

For useful group membership data, collect enum4linux-ng output with group-member enumeration enabled. Multiple JSON files may be supplied by repeating `--enum4linux`.

## Manual Privileged Accounts

```bash
python3 credweave.py ntdsdump.txt \
  -a privileged.txt
```

The file is newline-separated and may contain either:

```text
admjdoe
CORP\admjdoe
```

`-a/--admins-file` is repeatable and complements rather than replaces BloodHound/enum4linux enrichment.

## Console Analysis

CredWeave prioritizes high-signal relationships before generic reuse:

1. Privilege Boundary Credential Reuse
2. Likely Standard / Privileged Identity Reuse
3. Enabled / Disabled Credential Reuse
4. Actionable Credential Reuse
5. Empty Passwords
6. Special Accounts
7. Disabled-Only Credential Reuse

Large groups are compressed by default. For example:

```text
0e229487****************a01b28b4   228   ldap
                                              + 227 disabled account(s)
```

Use `--expand` to enumerate every account.

### Console Legend

```text
[T0] Tier 0
[P]  Privileged
[A]  Admin-like name
[D]  Disabled
[!]  Conflicting account status
```

`[A]` is a naming heuristic, not proof of privilege.

## Password Intelligence

Password statistics are shown automatically whenever `--potfile` is supplied. There is no separate enable flag because no plaintext statistics can be calculated without recovered plaintexts. To load a potfile while suppressing the statistics section, use:

```bash
python3 credweave.py ntdsdump.txt \
  --potfile client.pot \
  --no-password-stats             Suppress cracked-password statistics normally shown with --potfile

This does not disable potfile-backed functionality such as cracked-credential correlation, Tier 0 recovery analysis, or adaptive cracking workflows.

### Password Length (account-weighted)

**Account-weighted** means each account using a recovered password contributes one observation to the password-length statistics. A password reused by 20 accounts therefore contributes 20 observations, while a password used by one account contributes one.

This intentionally measures the password-length exposure of the **account population**, not merely the characteristics of the unique cracked-password corpus. For example, if one 8-character password is shared by 50 accounts and one 16-character password is used by a single account, the account-weighted view reflects that most affected accounts are protected by the 8-character password.

This is distinct from a unique-password-weighted calculation, where each distinct plaintext would count exactly once regardless of reuse. For pentest reporting, the account-weighted view is generally more representative of how password characteristics affect the recovered account population.

When a hashcat potfile is supplied, CredWeave analyzes the cracked corpus in the context of the accounts that own those credentials.

```bash
python3 credweave.py ntdsdump.txt \
  --bloodhound bloodhound.zip \
  --potfile ~/.local/share/hashcat/hashcat.potfile
```

The `Cracked Password Intelligence` section includes:

- user-account and unique-hash crack rates
- enabled-account crack rate
- privileged and Tier 0 crack rates
- account-weighted password-length distribution
- common password structural families
- character-set distributions
- observed Hashcat masks
- obvious username-derived passwords

Example:

```text
=== Cracked Password Intelligence ===
[i] User accounts          716 / 1785  (40.1%)
[i] Enabled accounts       370 / 941   (39.3%)
[i] Privileged accounts      6 / 25    (24.0%)
[i] Tier 0 accounts          6 / 25    (24.0%)
[i] Unique NT hashes       375 / 1300  (28.8%)

Password Length (account-weighted)
  10:241  12:189  13:86  9:65  14:48

Common Families
  mixed                    325
  word+special+digits      148
  word+digits+special      122
  word+digits              119
```

The known empty-password NT hash is excluded from cracked-password statistics, masks, adaptive cracking material, and the ordinary `Cracked Credentials` table. Empty-password accounts remain visible in their dedicated analysis section.

## Priority Cracking Opportunities

CredWeave uses account context to prioritize remaining uncracked NT hashes.

```text
=== Priority Cracking Opportunities ===
Score  Hash                                      Accounts  Why
----------------------------------------------------------------------------------------------------
  110  344330db****************4ed6be16                 2  Tier 0, 2 enabled, reused x2
  103  112fd779****************9d93123c                 1  Tier 0, 1 enabled
```

Priority scoring favors high-value conditions such as:

- Tier 0 accounts
- privileged accounts
- admin-like identities
- enabled accounts
- credentials reused by multiple accounts

The score is a cracking-workflow heuristic, not a vulnerability severity rating.

## Adaptive Cracking

CredWeave can feed patterns learned from already-cracked credentials back into the next cracking pass.

```bash
python3 credweave.py ntdsdump.txt \
  --bloodhound bloodhound.zip \
  --potfile hashcat.potfile \
  --crack-out uncracked.txt \
  --generate-candidates credweave.word \
  --generate-rules credweave.rule \
  --generate-masks credweave.hcmask
```

Outputs:

```text
credweave.word    target-derived source/base words
credweave.rule    target-derived Hashcat mangling rules
credweave.hcmask  Hashcat masks observed in the cracked corpus
```

The rule generator currently derives conservative transformations from the target's own cracked corpus, including capitalization, prefixes and suffixes, and common leetspeak substitutions. The generated source words, rules, and masks are deduplicated.

This supports an iterative engagement workflow:

```text
Existing potfile
      |
      v
CredWeave analyzes cracked corpus
      |
      v
Generate target-specific words / rules / masks
      |
      v
Hashcat attacks remaining hashes
      |
      v
Updated potfile
      |
      +----> rerun CredWeave
```

The cracked corpus is inherently biased toward attacks that have already succeeded. Treat generated patterns as target-specific cracking hypotheses rather than a complete model of the organization's password population.

### Example Hashcat Workflow

```bash
hashcat -m 1000 uncracked.txt credweave.word \
  -r credweave.rule
```

Observed masks can also be selected for focused mask attacks based on the engagement's cracking budget and the frequency of the pattern.

## Plaintext Display

When `--potfile` is supplied, recovered passwords are masked by default in console output, including the general **Cracked Credentials** section and **Cracked Tier 0 Accounts** output. This keeps routine terminal captures and reporting screenshots from exposing recovered client passwords.

Use `--show-plaintext` when the actual recovered values are required:

```bash
python3 credweave.py ntdsdump.txt \
  --potfile client.pot \
  --show-plaintext
```

`--show-plaintext` is a global display control for recovered plaintexts. It does not change the potfile or cracking artifacts.

When plaintexts are masked, CredWeave also avoids deriving the visible Password-column width or row ordering from hidden plaintext values.

## Account Status Enrichment

CredWeave tracks enabled/disabled state from the credential dump when status metadata such as `(status=Disabled)` is present. When dump status is absent and `--bloodhound` is supplied, CredWeave automatically enriches matching accounts with BloodHound account state when the supplied BloodHound dataset exposes `enabled` or `userAccountControl` properties.

Both BloodHound Legacy and BloodHound CE JSON/ZIP exports are supported. Account-state availability depends on the collection/export contents, not merely whether the file is Legacy or CE. Some valid BloodHound datasets contain no enabled/disabled property at all. CredWeave detects that condition and leaves otherwise-unresolved accounts as `Unknown` rather than inferring status.

Status resolution follows this precedence:

```text
Explicit dump status
        ↓
BloodHound / enrichment status
        ↓
Unknown
```

BloodHound parsing accepts normalized `enabled` properties across common boolean, numeric, and string representations. CredWeave can also derive account state from `userAccountControl` when that value is available.

Explicit dump status remains authoritative because it is associated directly with the credential collection being analyzed. CredWeave still retains contradictory observations from enrichment sources so status disagreements are detectable rather than silently discarded.

This enrichment feeds the rest of the analysis automatically, including:

- actionable versus disabled-only credential reuse
- enabled/disabled credential reuse
- Tier 0 recovery state
- affected-resource output
- account-weighted password intelligence and cracking prioritization

The BloodHound import summary reports the detected JSON schema version and how many account-status observations were recovered:

```text
[i] BloodHound bloodhound.zip: 1200 user record(s), 1500 group record(s), 9000 resolved membership(s), 1200 status observation(s) | JSON schema v6
```

If the supplied BloodHound data contains no account-state properties, CredWeave says so explicitly:

```text
[!] BloodHound user data contains no enabled/disabled account-state properties
    (enabled/userAccountControl). Accounts without dump-derived status will remain Unknown.
[i] For secretsdump.py collections, include --user-status to embed account status in the hash dump.
```

For Impacket `secretsdump.py`, using `--user-status` is recommended when producing input for CredWeave because it places account status alongside the dumped credential material. Dump-derived status takes precedence over enrichment sources.

## Tier 0 Credential Recovery

When a potfile and privilege-enrichment data are supplied, CredWeave can separate recovered and unrecovered Tier 0 identities. This answers the operationally important question of whether recovered credentials include high-value accounts rather than treating every crack as equally significant.

```bash
python3 credweave.py ntdsdump.txt \
  --bloodhound bloodhound.zip \
  --potfile client.pot \
  --cracked-t0 \
  --uncracked-t0
```

Example:

```text
=== Cracked Tier 0 Accounts ===
[i] 2 Tier 0 account(s) cracked: 2 enabled, 0 disabled, 0 unknown/conflict
Account         Status    Privilege   Password
------------------------------------------------------------
admeggsample    Enabled   Tier 0      ********
svc_example     Enabled   Tier 0      ********

=== Uncracked Tier 0 Accounts ===
[i] 3 Tier 0 account(s) remain uncracked: 2 enabled, 1 disabled, 0 unknown/conflict
Account         Status    Privilege
------------------------------------------------------------
admexample2     Enabled   Tier 0
svc_sccm        Enabled   Tier 0
admlegacy       Disabled  Tier 0
```

Recovered plaintexts are masked by default throughout CredWeave output. Explicitly display plaintexts with:

```bash
python3 credweave.py ntdsdump.txt \
  --bloodhound bloodhound.zip \
  --potfile client.pot \
  --cracked-t0 \
  --show-plaintext
```

Generate a deduplicated Hashcat-ready file containing only unrecovered Tier 0 NT hashes:

```bash
python3 credweave.py ntdsdump.txt \
  --bloodhound bloodhound.zip \
  --potfile client.pot \
  --crack-out-t0 t0-uncracked.txt
```

The Tier 0 recovery options require `--potfile`. Tier 0 classification comes from the privilege-enrichment data available to CredWeave, such as BloodHound or explicit privileged-account input.

## Candidate Normalization

Target-derived candidate words are emitted as lowercase, deduplicated lexical seeds. Case variants are intentionally not duplicated in `--generate-candidates` output because capitalization mutations belong to the Hashcat rule layer.

For example, observations such as:

```text
Example
example
EXAMPLE
```

produce a single base candidate:

```text
example
```

Observed capitalization is still analyzed when generating rules, so normalization does not discard casing intelligence. Adaptive combinator token sets use the same canonicalization strategy to avoid spending candidate workload on redundant case variants.

## Adaptive Rule Generation

CredWeave uses recovered target passwords as a target-specific rule-learning corpus. Rule generation is split conceptually into confidence tiers:

**Tier 1: Observed transformations.** CredWeave reproduces capitalization, prefixes, suffixes, and supported leetspeak substitutions actually observed in recovered passwords.

**Tier 2: Generalized recurring behavior.** Transformations observed repeatedly are promoted into reusable rules. This includes recurring capitalization behavior, leetspeak substitutions, and observed year/symbol suffix structures.

**Tier 3: Conservative extrapolation.** When a modern year is observed in a password suffix, CredWeave generates adjacent-year hypotheses (`year - 1` and `year + 1`) using the same observed suffix structure. This is intended to catch common password-rotation behavior without exploding the candidate space.

For example, a corpus containing patterns similar to:

```text
Spring2025!
Autumn2025!
Welcome2026!
```

can teach CredWeave that title-style capitalization plus a year and `!` is target-relevant. The candidate wordlist still contains lowercase lexical seeds, while the rule file carries the capitalization and suffix transformations.

The generated rule file preserves confidence ordering: baseline transformations first, then exact observed rules, generalized recurring rules, and finally extrapolated rules. Duplicate rules are removed across tiers.

Leetspeak generation is also corpus-aware. Supported substitutions include common forms such as `a -> @`, `a -> 4`, `e -> 3`, `i -> 1`, `o -> 0`, `s -> $`, `s -> 5`, and `t -> 7`. Repeatedly observed substitutions are promoted into the generalized layer.

This design keeps candidate generation focused on lexical material while using the recovered corpus to learn how the target population tends to transform that material.

## Adaptive Attack Planning

CredWeave can turn the cracked corpus into a ready-to-use cracking workspace. In addition to target-derived words, rules, and masks, it derives conservative left/right token sets for combinator attacks and estimates the resulting candidate workload.

```bash
python3 credweave.py ntdsdump.txt \
  --bloodhound bloodhound.zip \
  --potfile client.pot \
  --adaptive-plan \
  --attack-dir ./credweave-attack \
  --hashcat-bin /usr/bin/hashcat \
  --combinator-bin /usr/share/hashcat-utils/combinator.bin
```

If `hashcat` and `combinator.bin` are already available in `PATH`, the final two options can be omitted.

Example:

```text
=== Adaptive Attack Plan ===
[i] 549 source word(s), 478 rule(s), 194 observed mask(s)
[i] Combinator sets: 569 left x 191 right
[i] Remaining unique NT hashes: 904

Estimated Candidate Workload
  Base words + rules       262,422
  Combinator               108,679
  Combinator + rules       51,348,562

Suggested Passes
  1. Target-derived wordlist + generated rules
  2. Left/right combinator corpus
  3. Combinator output + generated rules
  4. High-frequency observed masks
```

`--attack-dir` creates:

```text
credweave-attack/
├── uncracked.txt
├── credweave.word
├── credweave.rule
├── credweave.hcmask
├── credweave.left
├── credweave.right
├── attack-plan.txt
└── credweave-crack.sh
```

The generated runner preserves the supplied potfile path, is dry-run by default, and can be launched from any working directory:

```bash
./credweave-attack/credweave-crack.sh
./credweave-attack/credweave-crack.sh --run
```

Execution uses three explicit passes:

```text
PASS 1/3: Target-Derived Words + Rules
PASS 2/3: Combinator
PASS 3/3: Combinator + Rules
```

Combinator output is streamed directly into Hashcat for passes 2 and 3 instead of being written to a potentially large intermediate wordlist.

Runtime paths can also be overridden:

```bash
HASHCAT=/opt/hashcat/hashcat \
COMBINATOR=/opt/hashcat-utils/bin/combinator.bin \
POTFILE=/cases/client/client.pot \
MODE=1000 \
./credweave-attack/credweave-crack.sh --run
```

After additional credentials are recovered, rerun CredWeave against the updated potfile. Newly recovered plaintexts become input for the next generation of candidate words, rules, masks, and combinator sets.

## Cracked Credentials

Provide a hashcat potfile:

```bash
python3 credweave.py ntdsdump.txt \
  --potfile ~/.local/share/hashcat/hashcat.potfile
```

CredWeave correlates recovered plaintexts with accounts and presents them in a wrapped table:

```text
=== Cracked Credentials ===

Password                   Accounts  Users
--------------------------------------------------------------------------------
Welcome2026!                      2  admeggsample [T0], eggsample
```

Large cracked groups use the same signal compression as the reuse report. `--expand` disables compression.

Plaintext credentials are intentionally not included in the reporting bundle's affected-resource exports.

## Cracking Exports

Export unique NT hashes that are not already present in the supplied potfile:

```bash
python3 credweave.py ntdsdump.txt \
  --potfile hashcat.potfile \
  --crack-out ntlm-uncracked.txt
```

Export LM hashes:

```bash
python3 credweave.py ntdsdump.txt \
  --lm-crack-out lm.txt
```

The known empty-password NT hash and disabled/empty LM sentinel are excluded from cracking exports.

## LM Hash Analysis

```bash
python3 credweave.py ntdsdump.txt --lm
```

This reports accounts for which legacy LM credential material was recovered.

## Diffing Credential Dumps

```bash
python3 credweave.py current.txt \
  --diff previous.txt
```

The diff identifies:

- new accounts
- removed accounts
- accounts whose NT credential material changed

This is useful for repeat assessments and long-running engagements.

## Affected Resources Output

CredWeave can generate report-ready affected-resource tables:

```bash
python3 credweave.py ntdsdump.txt \
  --bloodhound bloodhound.zip \
  --finding implied-trust \
  --affected-resources affected-resources.csv
```

The output is normalized to one relationship per row. It intentionally omits credential plaintexts and hashes.

Columns include:

```text
Finding
Affected Resource
Related Resource
Relationship
Affected Status
Related Status
Affected Privilege
Related Privilege
Detail
```

### Finding Selectors

Available selectors:

```text
implied-trust
privileged-reuse
password-reuse
empty-passwords
lm-hashes
all
```

Example:

```bash
python3 credweave.py ntdsdump.txt \
  --bloodhound bloodhound.zip \
  --finding privileged-reuse \
  --affected-resources privileged-reuse.csv
```

`implied-trust` is intentionally selective. It focuses on privilege-boundary credential reuse and likely standard/privileged identity relationships rather than treating every ordinary password-reuse pair as an implied-trust relationship.

### Affected Resource Formats

```bash
--affected-resources-format csv
--affected-resources-format tsv
--affected-resources-format markdown
```

CSV is the default.

Example Markdown appendix export:

```bash
python3 credweave.py ntdsdump.txt \
  --bloodhound bloodhound.zip \
  --finding implied-trust \
  --affected-resources appendix.md \
  --affected-resources-format markdown
```

## Reporting Bundle

Generate a complete reporting workspace:

```bash
python3 credweave.py ntdsdump.txt \
  --bloodhound bloodhound.zip \
  --potfile hashcat.potfile \
  --finding implied-trust \
  --report-dir ./credweave-report
```

Output:

```text
credweave-report/
├── summary.txt
├── affected-resources.csv
├── credential-reuse.csv
├── privileged-reuse.csv
├── empty-passwords.csv
├── lm-hashes.csv
└── analysis.json
```

`affected-resources.csv` follows the selected `--finding`. The other artifacts retain broader analysis so the data can be reused for additional findings without rerunning CredWeave.

## CSV and JSON Analysis

Generic credential-reuse CSV:

```bash
python3 credweave.py ntdsdump.txt \
  -o credential-reuse.csv
```

Full machine-readable analysis:

```bash
python3 credweave.py ntdsdump.txt \
  --json analysis.json
```

Hashes are masked unless `--show-hashes` is supplied.

## Hash Display

By default:

```text
5e016b1e****************eab76535
```

To display/export complete hashes:

```bash
python3 credweave.py ntdsdump.txt --show-hashes
```

Use this deliberately. Masked hashes are generally better suited to screenshots and report artifacts.

## Account State

CredWeave tracks:

```text
Enabled
Disabled
Unknown
Conflict
```

Status may come from the credential dump or enrichment sources. Conflicting observations are retained and surfaced rather than silently choosing one source.

To hide disabled accounts from the general reuse table:

```bash
python3 credweave.py ntdsdump.txt --enabled-only
```

Relationship analysis still considers disabled accounts because a disabled privileged account sharing a credential with an enabled account can remain highly relevant.

## Empty Passwords

The known empty-password NT hash is treated as its own condition and is **not** counted as ordinary credential reuse.

This prevents a large collection of empty-password accounts from distorting reuse statistics or burying more meaningful relationships.

## Output Width

CredWeave normally detects terminal width automatically:

```bash
python3 credweave.py ntdsdump.txt
```

Override it for consistent screenshots:

```bash
python3 credweave.py ntdsdump.txt --width 160
```

Wrapping is based on visible account labels rather than ANSI escape sequences, so colored output remains aligned.

## Strict Parsing

By default, malformed records can be skipped so one ugly line does not ruin an engagement run.

To fail immediately instead:

```bash
python3 credweave.py ntdsdump.txt --strict
```

## Command Reference

```text
usage: credweave [-h] [enrichment] [credential intelligence] [analysis] [output] dump
```

### Enrichment

```text
--bloodhound PATH          BloodHound collector ZIP, directory, or JSON; repeatable
--enum4linux JSON          enum4linux-ng JSON; repeatable
-a, --admins-file FILE     Explicit privileged accounts; repeatable
```

### Credential Intelligence

```text
--potfile FILE                  hashcat potfile
--crack-out FILE                Write unique uncracked NT hashes
--lm-crack-out FILE             Write unique LM hashes
-l, --lm                        Report accounts storing LM hashes
--no-password-stats                Show cracked-password intelligence
--generate-candidates FILE      Write target-derived source/base words
--generate-rules FILE           Write target-derived Hashcat rules
--generate-masks FILE           Write observed Hashcat masks
--adaptive-plan                 Show target-derived adaptive attack plan
--attack-dir DIR                Write adaptive cracking workspace and runner
--hashcat-bin PATH              Hashcat executable for generated runner
--combinator-bin PATH           hashcat-utils combinator executable for generated runner
```

### Analysis

```text
--diff OLDDUMP             Compare against an older credential dump
--enabled-only             Hide disabled accounts from the general reuse table
--strict                   Abort on malformed dump records
--expand                   Fully enumerate large reuse groups
```

### Output

```text
-o, --output CSV                    Write credential-reuse CSV
--json FILE                         Write full JSON analysis
--affected-resources FILE           Write report-ready affected resources
--affected-resources-format FORMAT  csv, tsv, or markdown
--finding FINDING                   Select reporting finding
--report-dir DIR                    Write complete reporting bundle
--show-hashes                       Display/export complete hashes
-w, --width N                       Force console width
--version                           Display CredWeave version
```

## Suggested Engagement Workflow

A useful workflow after obtaining domain credential material:

```bash
python3 credweave.py ntdsdump.txt \
  --bloodhound bloodhound.zip \
  --enum4linux enum.json \
  --potfile ~/.local/share/hashcat/hashcat.potfile \
  --crack-out hashes-to-crack.txt \
  --generate-candidates credweave.word \
  --generate-rules credweave.rule \
  --generate-masks credweave.hcmask \
  --lm \
  --finding implied-trust \
  --report-dir ./credweave-report
```

Then:

1. Review privilege-boundary and identity-reuse relationships first.
2. Review enabled/disabled reuse for live accounts inheriting stale credentials.
3. Review `Priority Cracking Opportunities` for high-value uncracked credentials.
4. Feed `hashes-to-crack.txt` into the normal cracking workflow.
5. Use `credweave.word`, `credweave.rule`, and `credweave.hcmask` for a target-derived adaptive pass.
6. Rerun CredWeave with the updated potfile so newly cracked credentials feed the next analysis cycle.
7. Use the terminal output for evidence screenshots.
8. Use `affected-resources.csv` for the finding or appendix.
9. Retain `analysis.json` as the machine-readable engagement artifact.

## Security and Reporting Notes

Credential dumps, potfiles, plaintext credentials, and generated analysis artifacts are sensitive engagement data. Handle them according to the engagement's data-handling requirements.

CredWeave masks NT hashes by default and avoids exporting plaintext credentials into affected-resource/reporting artifacts. `--show-hashes` explicitly opts into full hash display.

## Authors

CredWeave was created by **Jaime Cabeza** and developed with assistance from **OpenAI's ChatGPT**.

The project grew out of real-world penetration-testing workflows for analyzing credential reuse, privilege relationships, recovered credential material, and target-specific cracking opportunities.

## Version

Current version:

```text
CredWeave 1.6.1
```

Check locally with:

```bash
python3 credweave.py --version
```

---

**CredWeave**  
*Find the relationships hiding in credential material.*
