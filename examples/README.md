# CredWeave Synthetic Demo

This directory contains a fully synthetic Active Directory credential corpus for demonstrating CredWeave without exposing engagement data.

The fixture intentionally includes:

- Tier 0 to standard-user credential reuse
- likely standard/admin identity reuse
- enabled/disabled credential reuse
- service-account credential reuse
- cracked and uncracked Tier 0 accounts
- target password patterns suitable for password-intelligence output

Run the demo from the repository root:

```bash
python3 credweave.py examples/sample-ntdsdump.txt \
  --bloodhound examples/sample-bloodhound.zip \
  --potfile examples/sample.pot \
  --cracked-t0 \
  --uncracked-t0 \
  --width 130
```

All accounts, hashes, passwords, SIDs, and BloodHound data in this directory are synthetic and exist only for demonstration/testing.
