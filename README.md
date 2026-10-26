# sharp-rsvg-rce-check

[![Tests](https://github.com/completetech-security/sharp-rsvg-rce-check/actions/workflows/tests.yml/badge.svg)](https://github.com/completetech-security/sharp-rsvg-rce-check/actions/workflows/tests.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-1E3A8A)
![No dependencies](https://img.shields.io/badge/dependencies-none-067647)
[![AGPL-3.0 or commercial license](https://img.shields.io/badge/license-AGPL--3.0%20%7C%20commercial-64748B)](LICENSING.md)

Assess **CVE-2026-96889 / GHSA-wq5f-xc86-pv6w**, the librsvg memory vulnerability used through Sharp, from explicit offline evidence. Copy `sharp_rsvg_rce_check.py` and run it with Python 3.10+. No packages, Node.js, companion files or network access are required.

The checker keeps the selected native library, reported version, provenance, platform, libc, SVG input path and hardening separate. It does not import Sharp, execute applications, decode an image, send a probe, test reachability or detect compromise. Every result retains `exploitability: not_tested`.

## Quick start

```sh
python sharp_rsvg_rce_check.py --sharp-version 0.35.4 --library-source bundled --sharp-build-source upstream
python sharp_rsvg_rce_check.py --sharp-version 0.35.5 --library-source bundled --sharp-build-source upstream
python sharp_rsvg_rce_check.py --library-source global --librsvg-version 2.63.2 --librsvg-build-source upstream
python sharp_rsvg_rce_check.py --inventory examples/inventory.json --format json
python sharp_rsvg_rce_check.py --inventory examples/inventory.json --format html --output report.html
```

Use `python3` or a versioned executable where appropriate; `python --version` must report 3.10 or later. `examples/inventory.json` is synthetic. Keep real inventories and reports outside version control. Existing reports are protected; `--force` permits deliberate replacement but never an input, its alias, a supplied logo or the checker itself.

`--library-source bundled` means the deployed process is reported to use the official Sharp bundle. `--sharp-build-source upstream` is an operator claim, not verified provenance. A Sharp package number alone cannot identify a global library. Use `--library-source global` with independent native-library evidence for that case; an unknown selection remains unknown.

## Reading the result

| Status | Meaning |
| --- | --- |
| `unknown` | Selection, exact version, provenance or supported rule coverage cannot establish the selected component's patch state. |
| `potentially_affected` | A reported official Sharp bundle is below its fix. Runtime conditions remain separate; this does not confirm exploitability. |
| `precondition_present` | That affected bundle and operator-reported conditions match the documented possible RCE conditions. No live verification was performed. |
| `mitigated_configuration` | An affected bundle remains recorded while an operator reports effective SVG blocking or Node PIE. It is not a patched or safe result. |
| `fixed_version_reported` | The selected component meets its reviewed remediation threshold. This does not attest the deployed binary or patch set. |

Missing libc or PIE remains `unknown` in the precondition dimensions. A non-glibc platform or reported absence of an untrusted input path does not clear the underlying memory bug. PIE addresses the documented RCE condition; other memory-corruption impact can remain.

`--fail-on-finding` returns 1 for **every affected version**, including `mitigated_configuration`, because patching still needs review. `--fail-on-unknown` independently returns 1 for an unknown version assessment or unresolved conditions on an affected version. Operational errors return 2; interruption returns 130 and preserves completed results when output can be written.

## Verified rule snapshot

The [maintainer advisory](https://github.com/lovell/sharp/security/advisories/GHSA-wq5f-xc86-pv6w) and [GitHub advisory record](https://github.com/advisories/GHSA-wq5f-xc86-pv6w) were reviewed on **2026-10-24**.

| Evidence | Implemented comparison |
| --- | --- |
| Official Sharp bundle | Stable `0.x` below `0.35.5` is potentially affected; `0.35.5+` within `0.35.x` is a reported fix. Future release lines stay unknown in this snapshot. |
| Global librsvg | Independent upstream `2.63.2+` within `2.63.x` is reported remediation. Earlier versions stay unknown requiring vendor review: the advisory names the fix without a separate native-library affected-range lower bound. |
| Vendor/custom/unknown build provenance | Unknown; an upstream package number does not establish a backport or custom patch set. |
| Effective `VipsForeignLoadSvg` block | Separate decoder mitigation claim. |
| Node executable compiled with PIE | Separate RCE mitigation claim; not a library patch. |

Malformed, conflicting, qualified, prerelease and uncovered-future versions remain unknown. Contradictory Sharp/native-library observations also remain unknown. The embedded snapshot has no updater; consult the current vendor guidance for remediation.

Reports retain every distinct accepted exact Sharp and librsvg version in each
component's evidence detail, including conflicting observations. Repeated equal
values are deduplicated and sorted; qualified or malformed raw strings are not
exported. Retaining a candidate never selects it as the assessed version.

JSON, formula-neutralized CSV and a self-contained, script-free HTML report use the same validated evidence records. HTML supports escaped `--brand` and an optional bounded local raster `--logo`. See the [actual synthetic HTML example](docs/example-report.html); retained images in `docs/images/` are earlier concept artwork, not generated results.

## Documentation and development

- [Reference](docs/REFERENCE.md): input schema, CLI, limits, outputs and exit policy
- [Methodology](docs/METHODOLOGY.md): rule provenance, uncertainty and mitigation semantics
- [Evidence contract](docs/CONTRACT.md) and [inventory schema](schemas/inventory-v1.schema.json)
- [Implementation checklist](docs/IMPLEMENTATION.md) and [advisory research history](advisory.json)
- [Contributing](CONTRIBUTING.md), [security policy](SECURITY.md) and [agent instructions](AGENTS.md)

```sh
python tools/build.py --check
python -m unittest -v
python sharp_rsvg_rce_check.py --help
git diff --check
```

Tests use synthetic local fixtures. CI is configured for Python 3.10 and 3.14 on Linux, Windows and macOS; assess its result for the exact published commit separately from local verification. Edit `src/checker.py`, `src/adapters.py`, `vendor/common.py` or `rules/snapshot.json`, then rebuild with `python tools/build.py`. The generated checker has no runtime dependency on another repository.

## License

Copyright © 2026 CompleteTech LLC. [AGPL-3.0](LICENSE), or a separate [commercial license](LICENSING.md). Names and brand assets have separate [terms](BRAND_ASSETS.md).

Built by [CompleteTech LLC](https://complete.tech) · Innovation at Every Integration

An interruption after a complete report is published preserves that report and exits 130.

If an interrupt leaves file publication indeterminate, the checker exits 130 without retrying. Inspect the output before retrying; the diagnostic does not establish whether publication succeeded.

## Explicit local metadata and source adapters

```sh
python sharp_rsvg_rce_check.py --npm-lock examples/package-lock.example.json --evidence-root examples
python sharp_rsvg_rce_check.py --source examples/source.example.js --evidence-root examples --format html
python sharp_rsvg_rce_check.py --node-elf path/to/node --evidence-root path/to
python sharp_rsvg_rce_check.py --sbom path/to/bom.json --evidence-root path/to
```

The repeatable `--npm-lock`, `--sbom`, `--node-elf` and `--source` options require
`--evidence-root`. Selected files must resolve inside that directory; paths in
reports are relative. They may accompany existing inventory/version inputs, but
produce separate generated `adapter-*` asset records. Generated identifiers must
not collide with supplied inventory IDs. No directory search, package-manager
operation, application import, native execution or image decoding occurs.

All adapter results remain `unknown` with `not_tested` exploitability. Metadata
cannot identify a deployed native-library selection or publisher patch
provenance. It never fills operator preconditions, changes a separate version
assessment or establishes effective mitigation. The existing schema 1.0 evidence
contract carries these observations as inventory/source evidence and locations;
JSON, CSV and HTML use the same validated records.

- npm lock v1/v2/v3: extract Sharp package version observations, including nested
  instances and explicit aliases. Linked/malformed/qualified identities stay
  unknown. Legacy v2 dependency records are separate uncertain observations,
  never used to clear a conflicting primary entry. Registry URLs and scripts
  are not collected. Empty supported coverage does not establish absence.
- SBOM: support JSON CycloneDX 1.4/1.5/1.6 and SPDX 2.2/2.3 Sharp/librsvg package
  metadata. Names and versions remain supplied metadata, not linkage evidence;
  no external references are fetched and no package paths are opened.
- ELF: read the identification/header, at most 1,024 standard-size program
  headers and one interpreter string (512 bytes maximum). Support ELF32/64 in
  both byte orders; bound file size to 2 GiB and metadata reads to 58 KiB. Reject
  truncated/out-of-file tables/segments, duplicate interpreters, extended header
  counts and unsupported layouts. ET_DYN with an interpreter is a dynamic
  executable candidate; ET_DYN alone can also be a shared library or static PIE.
  ET_EXEC and interpreter basename hints are reported without asserting Node
  identity, loaded libc, runtime PIE, patch state or safety. Exact loader paths
  are not reported. Other hardening features are not analyzed.
- Source: explicitly select JS/TS files. Simple Sharp default imports/CommonJS
  bindings identify factory and block/unblock call candidates with relative
  lines. An SVG-loader marker in a bounded local window can belong to unrelated
  code. No match, missing marker, unknown options, inactive blocks, shadowing,
  ordering or dynamic syntax never establishes effective blocking or input
  trust. Templates and regex/division ambiguity require manual review. Source
  strings/snippets are not reported.

Budgets: 100 adapter files, 1,000 combined result records, bounded 4 MiB JSON/text
reads and the existing JSON structure/depth limit; 10,000 package metadata
entries, 200,000 source tokens/file and 100 source candidates/file. Ordinary
regular-file checks require stable evidence copies, not a filesystem sandbox.
Output protection includes all selected evidence files and aliases, even with
--force. `--fail-on-unknown` includes these unknown adapter records.

Format provenance reviewed 2026-10-25: [Linux ELF header/program-header layouts](https://github.com/torvalds/linux/blob/master/include/uapi/linux/elf.h),
[npm lock grammar](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/),
[CycloneDX 1.6 schema](https://github.com/CycloneDX/specification/blob/master/schema/bom-1.6.schema.json) and
[SPDX package fields](https://spdx.github.io/spdx-spec/v2.3.1/package-information/).
The Linux Foundation gABI pages were access-denied; no access restriction was
bypassed. Advisory thresholds, rule date and native affected-range uncertainty
are unchanged. Edit `src/adapters.py` and rebuild with `python tools/build.py`.
