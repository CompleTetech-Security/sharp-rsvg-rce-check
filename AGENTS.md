# Repository instructions

Read [README.md](README.md), [CONTRIBUTING.md](CONTRIBUTING.md),
[SECURITY.md](SECURITY.md), and [docs/IMPLEMENTATION.md](docs/IMPLEMENTATION.md)
before changing this project.

## Scope and current state

This repository covers only **CVE-2026-96889** (Sharp librsvg memory vulnerability). Its aliases
refer to the same exploit. Keep unrelated vulnerabilities in separate repositories.
The repository implements an offline evidence checker. Do not add network
scanning, application execution, image decoding or exploit payloads.

## Project map

- `sharp_rsvg_rce_check.py`: generated, standalone Python 3.10+ executable.
- `src/checker.py`, `src/adapters.py`, `vendor/common.py`: product logic and vendored evidence/report helpers.
- `rules/snapshot.json`: dated, source-linked enabled rule snapshot.
- `tools/build.py`: deterministic single-file build and release checksums.
- `test_assessment.py`, `test_contract.py`: synthetic offline behavior tests.
- `advisory.json`: source-preserving research record and implementation state.
- `README.md`, `docs/REFERENCE.md`, `docs/METHODOLOGY.md`: actual behavior and evidence limits.
- `docs/IMPLEMENTATION.md`: local implementation and verification checklist.
- `LICENSING.md`, `CONTRIBUTING.md`, `BRAND_ASSETS.md`: licensing and contribution terms.

## Implementation constraints

Follow the established [node2shell-check](https://github.com/completetech-security/node2shell-check) and [php2shell-check](https://github.com/completetech-security/php2shell-check) conventions. Prefer a small, auditable,
dependency-free checker when appropriate. Do not turn this project into a generic
product scanner or execute exploit payloads.

Version claims are evidence, not verified runtime state. Keep missing, conflicting,
malformed, prerelease, vendor/custom-build, backport, and uncovered-future cases
uncertain. Never equate `potentially_affected` with confirmed exploitability or
`fixed_version_reported` with a safety guarantee. Exploitability remains
`not_tested`. Configuration hints and source patterns are not proven reachability.

Keep offline modes offline. Any future collector must avoid application imports,
secrets, environment variables, hostnames, process arguments, and application data.
If passive fetching is justified, preserve verified TLS, relevant robots policy,
an honest User-Agent, pacing, bounds, conservative redirects, and no inherited
environment proxy. Editing this repository does not authorize scanning real targets.

Update sources and verification dates only after primary-source review. Preserve
all advisory caveats and document unresolved conflicts. Do not infer selected
native-library state from a Sharp package when global linkage is possible.
Preserve independent global-library evidence, unknown provenance, the unpublished
native affected-range lower bound, and separate SVG blocking/Node PIE mitigations.
Missing libc or PIE never establishes safety.

## Validation and delivery

Use focused synthetic cases and local-only fixtures for meaningful behavior tests.
Do not invent passing tests, add prose-only tests, or publish
private assessments. Keep CLI, schemas, methodology, and README aligned. Distinguish
local results from hosted CI on the exact published commit. Preserve unrelated
work and follow the licensing and brand policies linked above.

```sh
python tools/build.py --check
python -m unittest -v
python sharp_rsvg_rce_check.py --help
git diff --check
```

Edit locally vendored helpers and product source, then rebuild. Preserve protected
input aliases, no-clobber reports, bounded reads, controlled errors and completed
results on interruption. Verify hosted CI for the exact published commit.
