<p align="center">
  <img src="docs/images/banner.png" alt="sharp-rsvg-rce-check by CompleteTech LLC" width="100%">
</p>

# sharp-rsvg-rce-check

[![Tests](https://github.com/completetech-security/sharp-rsvg-rce-check/actions/workflows/tests.yml/badge.svg)](https://github.com/completetech-security/sharp-rsvg-rce-check/actions/workflows/tests.yml)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-1E3A8A)
![No dependencies](https://img.shields.io/badge/dependencies-none-067647)
[![AGPL-3.0 or commercial license](https://img.shields.io/badge/license-AGPL--3.0%20%7C%20commercial-64748B)](LICENSING.md)

An offline evidence checker for **CVE-2026-96889 / GHSA-wq5f-xc86-pv6w**, the librsvg memory vulnerability used through Sharp. It classifies the versions, provenance and configuration that you report; it does not inspect a running system.

## Contents

- [Scope](#scope)
- [Requirements](#requirements)
- [Quick start](#quick-start)
- [Synthetic report preview](#synthetic-report-preview)
- [Usage](#usage)
- [Reading the result](#reading-the-result)
- [Verified rule snapshot](#verified-rule-snapshot)
- [Local metadata and source adapters](#local-metadata-and-source-adapters)
- [Outputs and report protection](#outputs-and-report-protection)
- [Limitations](#limitations)
- [Documentation](#documentation)
- [Development](#development)
- [License](#license)

## Scope

The checker keeps the selected native library, reported version, provenance, platform, libc, SVG input path and hardening separate. It does not import Sharp, execute applications, decode an image, send a probe, test reachability or detect compromise. Every result retains `exploitability: not_tested`.

Results describe supplied evidence, not verified runtime state. Use the checker only for assets you are authorized to assess, and keep real inventories and reports outside version control.

## Requirements

- Python 3.10 or later. Use `python3` or a versioned executable where appropriate; `python --version` must report 3.10 or later.
- The single file `sharp_rsvg_rce_check.py`. No packages, Node.js, companion files or network access are required.

## Quick start

```sh
python sharp_rsvg_rce_check.py --sharp-version 0.35.4 --library-source bundled --sharp-build-source upstream
python sharp_rsvg_rce_check.py --sharp-version 0.35.5 --library-source bundled --sharp-build-source upstream
python sharp_rsvg_rce_check.py --library-source global --librsvg-version 2.63.2 --librsvg-build-source upstream
python sharp_rsvg_rce_check.py --inventory examples/inventory.json --format json
python sharp_rsvg_rce_check.py --inventory examples/inventory.json --format html --output report.html
```

The first two commands assess an official Sharp bundle below and at its reported fix, the third an independently reported global librsvg, and the last two a synthetic inventory. `examples/inventory.json` is synthetic. Without `--output`, the report is printed to stdout (JSON by default).

## Synthetic report preview

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/images/report-dark.png">
  <img src="docs/images/report-light.png" alt="Sharp / librsvg synthetic report" width="100%">
</picture>

[Open the synthetic example report](docs/example-report.html). Example data only; this is not a live assessment. The preview images are screenshots of that example, not output from a real system.

## Usage

Run `python sharp_rsvg_rce_check.py --help` for the complete option list. Supply an inventory, at least one reported version or explicit adapter files:

- `--inventory FILE`, a bounded schema-v1 JSON inventory. It cannot be combined with per-asset options.
- A reported version with per-asset options such as `--sharp-version`, `--librsvg-version`, `--library-source`, `--platform`, `--libc`, `--node-pie`, `--svg-decoder` and `--untrusted-svg`. `--sharp-version` and `--librsvg-version` are repeatable so that conflicting observations are preserved rather than merged.
- Explicit local metadata or source files, which also require `--evidence-root` (see [Local metadata and source adapters](#local-metadata-and-source-adapters)).

No directory is scanned implicitly. Field values, bounds and the inventory format are in the [reference](docs/REFERENCE.md) and the [inventory schema](schemas/inventory-v1.schema.json).

### Library selection and provenance

- `--library-source bundled` means the deployed process is reported to use the official Sharp bundle.
- `--sharp-build-source upstream` is an operator claim, not verified provenance.
- A Sharp package number alone cannot identify a global library. Use `--library-source global` with independent native-library evidence (`--librsvg-version`, `--librsvg-build-source`) for that case.
- An unknown selection remains unknown.

## Reading the result

| Status | Meaning |
| --- | --- |
| `unknown` | Selection, exact version, provenance or supported rule coverage cannot establish the selected component's patch state. |
| `potentially_affected` | A reported official Sharp bundle is below its fix. Runtime conditions remain separate; this does not confirm exploitability. |
| `precondition_present` | That affected bundle and operator-reported conditions match the documented possible RCE conditions. No live verification was performed. |
| `mitigated_configuration` | An affected bundle remains recorded while an operator reports effective SVG blocking or Node PIE. It is not a patched or safe result. |
| `fixed_version_reported` | The selected component meets its reviewed remediation threshold. This does not attest the deployed binary or patch set. |

The version assessment of the selected component is separate from its platform, precondition and mitigation dimensions. `fixed_version_reported` is a reported-version result: it is neither a verified deployed patch nor a safety guarantee, and `potentially_affected` is not confirmed exploitability. A global result classifies the independently supplied native library, not an installed Sharp package.

Missing libc or PIE remains `unknown` in the precondition dimensions. A non-glibc platform or reported absence of an untrusted input path does not clear the underlying memory bug. PIE addresses the documented RCE condition; other memory-corruption impact can remain.

### Exit codes

Operational failures (exit 2) are distinct from assessment results.

| Exit | Meaning |
| --- | --- |
| `0` | Completed and no enabled gate matched. Unknown evidence does not fail by default. |
| `1` | `--fail-on-finding` matched an affected version, **including** `mitigated_configuration`, because patching still needs review; or `--fail-on-unknown` matched an unknown version assessment or unresolved conditions on an affected version. The two gates are independent. |
| `2` | Argument, input or output error, hard limit or schema validation failure. |
| `130` | Interrupted. Completed assets are preserved with `complete=false` when the report can be written. |

An interruption after a complete report is published preserves that report and exits 130. If an interrupt leaves file publication indeterminate, the checker exits 130 without retrying; inspect the output before retrying, because the diagnostic does not establish whether publication succeeded. Once stdout publication starts, an interruption can leave a partial document, and no second report is appended.

## Verified rule snapshot

The [maintainer advisory](https://github.com/lovell/sharp/security/advisories/GHSA-wq5f-xc86-pv6w) and [GitHub advisory record](https://github.com/advisories/GHSA-wq5f-xc86-pv6w) were reviewed on **2026-10-24**.

| Evidence | Implemented comparison |
| --- | --- |
| Official Sharp bundle | Stable `0.x` below `0.35.5` is potentially affected; `0.35.5+` within `0.35.x` is a reported fix. Future release lines stay unknown in this snapshot. |
| Global librsvg | Independent upstream `2.63.2+` within `2.63.x` is reported remediation. Earlier versions stay unknown requiring vendor review: the advisory names the fix without a separate native-library affected-range lower bound. |
| Vendor/custom/unknown build provenance | Unknown; an upstream package number does not establish a backport or custom patch set. |
| Effective `VipsForeignLoadSvg` block | Separate decoder mitigation claim. |
| Node executable compiled with PIE | Separate RCE mitigation claim; not a library patch. |

Malformed, conflicting, qualified, prerelease and uncovered-future versions remain unknown. Contradictory Sharp/native-library observations also remain unknown. The embedded snapshot has no updater and runtime assessment never fetches rule updates; consult the current vendor guidance for remediation. See [Methodology](docs/METHODOLOGY.md) for rule provenance.

## Local metadata and source adapters

```sh
python sharp_rsvg_rce_check.py --npm-lock examples/package-lock.example.json --evidence-root examples
python sharp_rsvg_rce_check.py --source examples/source.example.js --evidence-root examples --format html
python sharp_rsvg_rce_check.py --node-elf path/to/node --evidence-root path/to
python sharp_rsvg_rce_check.py --sbom path/to/bom.json --evidence-root path/to
```

The repeatable `--npm-lock`, `--sbom`, `--node-elf` and `--source` options require `--evidence-root`. Selected files must resolve inside that directory; paths in reports are relative. They may accompany existing inventory or version inputs, but produce separate generated `adapter-*` asset records. Generated identifiers must not collide with supplied inventory IDs. No directory search, package-manager operation, application import, native execution or image decoding occurs.

All adapter results remain `unknown` with `not_tested` exploitability. Metadata cannot identify a deployed native-library selection or publisher patch provenance. It never fills operator preconditions, changes a separate version assessment or establishes effective mitigation. The existing schema 1.0 evidence contract carries these observations as inventory/source evidence and locations; JSON, CSV and HTML use the same validated records.

| Adapter | Behavior and limits |
| --- | --- |
| npm lock (v1/v2/v3) | Extracts Sharp package version observations, including nested instances and explicit aliases. Linked, malformed and qualified identities stay unknown. Legacy v2 dependency records are separate uncertain observations, never used to clear a conflicting primary entry. Registry URLs and scripts are not collected. Empty supported coverage does not establish absence. |
| SBOM | JSON CycloneDX 1.4/1.5/1.6 and SPDX 2.2/2.3 Sharp/librsvg package metadata. Names and versions remain supplied metadata, not linkage evidence; no external references are fetched and no package paths are opened. CycloneDX component namespaces (`group`) must be text; a nonempty namespace is not treated as an unscoped Sharp/librsvg identity. Nested components are traversed independently. Unsupported identity remains unknown coverage. |
| ELF (`--node-elf`) | Reads the identification/header, at most 1,024 standard-size program headers and one interpreter string (512 bytes maximum). Supports ELF32/64 in both byte orders; file size is bounded to 2 GiB and metadata reads to 58 KiB. Truncated or out-of-file tables/segments, duplicate interpreters, extended header counts and unsupported layouts are rejected. `ET_DYN` with an interpreter is a dynamic executable candidate; `ET_DYN` alone can also be a shared library or static PIE. `ET_EXEC` and interpreter basename hints are reported without asserting Node identity, loaded libc, runtime PIE, patch state or safety. Exact loader paths are not reported. Other hardening features are not analyzed. |
| Source (`--source`) | Explicitly selected JS/TS files. Simple Sharp default imports and CommonJS bindings identify factory and block/unblock call candidates with relative lines. An SVG-loader marker in a bounded local window can belong to unrelated code. No match, missing marker, unknown options, inactive blocks, shadowing, ordering or dynamic syntax never establishes effective blocking or input trust. Templates and regex/division ambiguity require manual review. Source strings and snippets are not reported. |

Budgets: 100 adapter files, 1,000 combined result records, bounded 4 MiB JSON/text reads and the existing JSON structure/depth limit; 10,000 package metadata entries, 200,000 source tokens per file and 100 source candidates per file. Ordinary regular-file checks require stable evidence copies, not a filesystem sandbox. Output protection includes all selected evidence files and aliases, even with `--force`. `--fail-on-unknown` includes these unknown adapter records.

Format provenance was reviewed 2026-10-25: [Linux ELF header/program-header layouts](https://github.com/torvalds/linux/blob/master/include/uapi/linux/elf.h), [npm lock grammar](https://docs.npmjs.com/cli/v11/configuring-npm/package-lock-json/), [CycloneDX 1.6 schema](https://github.com/CycloneDX/specification/blob/master/schema/bom-1.6.schema.json) and [SPDX package fields](https://spdx.github.io/spdx-spec/v2.3.1/package-information/). The Linux Foundation gABI pages were access-denied; no access restriction was bypassed. Advisory thresholds, rule date and native affected-range uncertainty are unchanged.

## Outputs and report protection

`--format json|csv|html` defaults to JSON on stdout; `--output FILE` publishes an atomic report in an existing directory. JSON, formula-neutralized CSV and a self-contained, script-free HTML report use the same validated evidence records. HTML escapes dynamic text, blocks remote resources and supports an escaped `--brand` and an optional bounded local raster `--logo` (HTML only, no logo by default).

- **Protected output:** an existing destination is refused unless `--force` is given. `--force` never replaces an input, its alias, a supplied logo or the checker itself. Reports are not incremental checkpoints, so abrupt termination or an output failure can prevent publication.
- **Provenance:** every report includes one UTC run assessment timestamp, the exact standalone executable SHA-256, rule snapshot ID/date/hash and completeness. Empty and interrupted CSV summaries retain the same provenance. Assessment time is distinct from rule verification and evidence acquisition; build identity never attests a deployed patch. Library callers can inject time and build metadata to keep synthetic calls reproducible.
- **Version observations:** reports retain every distinct accepted exact Sharp and librsvg version in each component's evidence detail, including conflicting observations. Repeated equal values are deduplicated and sorted; qualified or malformed raw strings are not exported. Retaining a candidate never selects it as the assessed version.
- **Privacy:** the checker does not collect credentials, hostnames, environment variables, process arguments, source code or image data. Asset IDs and build numbers are operator-provided, so review them before sharing a report.

The [reference](docs/REFERENCE.md#outputs-and-report-protection) covers CSV columns, HTML options and symlink handling in detail.

## Limitations

- The checker evaluates reported evidence only. It does not verify that evidence, authenticate a binary or establish a deployed patch set.
- `upstream` provenance is an operator claim. Vendor, custom and unknown builds cannot produce a fixed assessment from an upstream number, and a package number does not establish a backport or custom patch set.
- Missing libc or PIE evidence, a non-glibc platform, a reported absence of untrusted SVG input and `mitigated_configuration` never establish that the system is patched or safe (see [Reading the result](#reading-the-result)).
- Malformed, conflicting, qualified, prerelease and uncovered-future versions remain unknown, and the embedded rule snapshot is not updated at runtime (see [Verified rule snapshot](#verified-rule-snapshot)).
- Local file checks are bounded and expect a stable evidence copy; they are not an operating-system sandbox against concurrent filesystem changes.

## Documentation

- [Reference](docs/REFERENCE.md): input schema, CLI, limits, outputs and exit policy
- [Methodology](docs/METHODOLOGY.md): rule provenance, uncertainty and mitigation semantics
- [Evidence contract](docs/CONTRACT.md) and [inventory schema](schemas/inventory-v1.schema.json)
- [Implementation checklist](docs/IMPLEMENTATION.md) and [advisory research history](advisory.json)
- [Contributing](CONTRIBUTING.md), [security policy](SECURITY.md) and [agent instructions](AGENTS.md)

## Development

```sh
python tools/build.py --check
python -m unittest -v
python sharp_rsvg_rce_check.py --help
git diff --check
```

Tests use synthetic local fixtures. CI is configured for Python 3.10 and 3.14 on Linux, Windows and macOS; assess its result for the exact published commit separately from local verification. Edit `src/checker.py`, `src/adapters.py`, `vendor/common.py` or `rules/snapshot.json`, then rebuild with `python tools/build.py`. The generated checker has no runtime dependency on another repository.

## License

Copyright © 2026 CompleteTech LLC. [AGPL-3.0](LICENSE), or a separate [commercial license](LICENSING.md). Names and brand assets, including the images in `docs/images/`, have separate [terms](BRAND_ASSETS.md).

Built by [CompleteTech LLC](https://complete.tech) · Innovation at Every Integration
