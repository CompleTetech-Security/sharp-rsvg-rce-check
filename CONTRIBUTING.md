# Contributing

This repository implements an offline evidence checker for **CVE-2026-96889**.
Start with the [implementation checklist](docs/IMPLEMENTATION.md).
Submit focused pull requests for this exploit. Report flaws requiring private
disclosure according to [SECURITY.md](SECURITY.md).

## Development expectations

Follow [AGENTS.md](AGENTS.md). Prefer a standalone Python 3.10+ checker with no
third-party runtime/test dependencies when suitable. Validate primary sources
before encoding affected or fixed ranges. Preserve evidence provenance and
`unknown` for missing or conflicting facts. Keep exploitability `not_tested`.

Use offline inventories, synthetic examples, mocks, and local fixtures. Do not
commit credentials, real target lists, private reports, or exploit payloads.
Network detection must be justified, optional, ordinary, bounded, and authorized.
Document implemented behavior and actual commands. Run the deterministic build
check, synthetic tests, CLI help and whitespace checks listed in AGENTS.md.
Keep bundled/global library selection and independent native-library provenance
separate. SVG blocking and Node PIE are mitigations, not library patch claims.

## Licensing of contributions

sharp-rsvg-rce-check follows the AGPL-3.0 / commercial licensing model described in
[LICENSING.md](LICENSING.md). By submitting a contribution, you confirm that you
have the right to submit it. You license it to the public under AGPL-3.0 and
grant CompleteTech LLC a perpetual, worldwide, royalty-free, irrevocable license
to use, modify, sublicense, and distribute it under any license, including a
commercial license. You keep the copyright in your contribution.
