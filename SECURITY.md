# Security policy

CIRSEC Baselines publishes configuration guidance, checks and fixes that people run as root
on production systems. A wrong fix is a security issue.

## What to report privately

- A fix (`remediation.scripts`, generated `remediate.sh` or Ansible role) that can break a system,
  lock administrators out, or weaken security, beyond what its `effects` declare.
- A check that reports `pass` on a non-compliant system (false negative).
- Generated code that can be abused: command injection through a parameter or tailoring value,
  unsafe temporary files, path traversal.
- A vulnerability in the tooling (`tools/`) or the release process.

Report it through [GitHub private vulnerability reporting](https://github.com/cirsec/baselines/security/advisories/new).
Do not open a public issue.

## What to report publicly

False positives, unclear wording, missing controls and broken mappings: open an issue with the
matching template.

## What happens next

We acknowledge within 7 days. Confirmed issues are fixed in a patch release of the affected
standard, and the fix is credited in the release notes unless you ask otherwise. A fix that was
dangerous is also flagged in the release notes so users of older releases can react.
