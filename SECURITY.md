# Security policy

Ilmarinen is experimental and not a production security product. No security support process or response time has been established yet.

## Reporting a vulnerability

If private vulnerability reporting is enabled for this repository, report suspected vulnerabilities through the **Security** tab using **Report a vulnerability**.

Do not publish exploit details, real Ilmarinen reports, baselines or file listings in public issues. They reveal file names and folder structure.

## Security model, in brief

- Ilmarinen is read-only. It never changes monitored files.
- A baseline's embedded digest only detects corruption. Tampering is detected only with a digest stored elsewhere (`--expected-digest`).
- Entries are inspected type-first and read only through the same verified object. If that can't be guaranteed, Ilmarinen fails closed (`unsafe-platform`).
- Reports contain relative file names; review them before sharing.
