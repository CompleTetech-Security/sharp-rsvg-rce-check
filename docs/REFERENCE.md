# Reference

## Inputs and execution

Run `python sharp_rsvg_rce_check.py --help` with Python 3.10+. Choose a JSON inventory or explicit per-asset options. No directory is scanned implicitly, and no application, package manager, Node executable, native library or configuration is run. Website URLs cannot provide the required evidence, so there is no network mode.

```sh
python sharp_rsvg_rce_check.py --sharp-version 0.35.4 --library-source bundled --sharp-build-source upstream --platform linux --libc glibc --node-pie disabled --svg-decoder enabled --untrusted-svg present
python sharp_rsvg_rce_check.py --library-source global --librsvg-version 2.63.2 --librsvg-build-source upstream --format csv
```

`--sharp-version` and `--librsvg-version` are repeatable (at most eight observations each). Repeated equal values agree; different values conflict. Accepted comparison values are plain three-part stable versions, without leading zeroes, whitespace, `v`, ranges, prereleases, vendor suffixes or build metadata. Invalid version text is not echoed in reports.

An explicit library selection is required for classification. `bundled` uses the Sharp threshold and Sharp provenance; `global` uses independent librsvg evidence and its own provenance. Supplying both sets of version evidence does not merge their identities. With a bundle, additional native-library evidence must have upstream provenance, stay within the reviewed 2.63 line and agree on the fix side; disagreement or possible backport evidence stays unknown. In global mode, missing Sharp metadata is allowed, but supplied malformed/conflicting Sharp observations keep the overall result unknown.

## JSON inventory

The [schema](../schemas/inventory-v1.schema.json) accepts an envelope with exactly `schema_version: "1.0"` and `records`, an array of 1–1,000 objects. Each object requires a unique opaque `asset_id`; other fields are optional and default to unknown or empty version observations.

| Field / corresponding CLI flag | Accepted values |
| --- | --- |
| `asset_id` / `--asset-id` | 1–64 ASCII letters/digits/dot/underscore/hyphen, starting with a letter/digit. CLI default: `asset-0001`. Do not use a hostname or secret. |
| `sharp_versions` / `--sharp-version` | Array of up to eight version strings, each 1–64 characters. |
| `librsvg_versions` / `--librsvg-version` | Independent native-library version observations, same bounds. |
| `library_source` / `--library-source` | `bundled`, `global`, `unknown`. |
| `sharp_build_source` / `--sharp-build-source` | `upstream`, `vendor`, `custom`, `unknown`. |
| `librsvg_build_source` / `--librsvg-build-source` | Independent native-library provenance, same values. |
| `platform` / `--platform` | `linux`, `other`, `unknown`. |
| `libc` / `--libc` | `glibc`, `musl`, `other`, `unknown`. |
| `node_pie` / `--node-pie` | `enabled`, `disabled`, `unknown`, `conflicting`. Refers to the deployed Node executable. |
| `svg_decoder` / `--svg-decoder` | `enabled`, `blocked`, `unknown`, `conflicting`. A blocked claim must cover effective `VipsForeignLoadSvg` blocking in the process. |
| `untrusted_svg` / `--untrusted-svg` | `present`, `absent`, `unknown`, `conflicting`, based on operator review of the input path. |

`upstream` is an operator claim; this tool does not authenticate a binary or vendor patch provenance. `vendor`, `custom` and `unknown` cannot produce a fixed assessment from an upstream number. Do not label a vendor package upstream merely to obtain a result.

Only documented fields are accepted. Duplicate JSON keys, unknown fields, duplicate asset IDs, wrong types, non-finite numbers and unsupported schema versions are input errors. UTF-8 with an optional BOM is accepted. The inventory is at most 4 MiB; JSON nesting is at most 40 levels and 200,000 nodes. Only regular files are read; final symlinks and special files such as FIFOs are rejected. Use a stable input copy; this local CLI is not an operating-system sandbox against concurrent filesystem changes.

The checker does not collect credentials, hostnames, environment variables, process arguments, source code or image data. Inventories contain operator-supplied evidence and should stay outside version control.

## Outputs and report protection

`--format json|csv|html` defaults to JSON on stdout. `--output FILE` publishes an atomic report in an existing directory. It refuses an existing destination unless `--force` is supplied. The scanner, inventory, supplied logo and their symlink/hard-link aliases remain protected with `--force`; output symlinks are rejected. No-clobber publication requires filesystem hard-link support and fails explicitly if unavailable. Reports are not incremental checkpoints; abrupt termination or output failure can prevent publication.

All formats share the [v1 evidence contract](CONTRACT.md). JSON includes the rule snapshot digest and `complete` flag, without a runtime timestamp. CSV serializes structured dimensions as JSON cells and prefixes strings that could become spreadsheet formulas. An interrupted report with no completed assets has a `record_type=summary` row. HTML escapes dynamic text, blocks remote resources, contains no scripts, supports printing, and accepts `--brand TEXT` and `--logo FILE` (PNG/JPEG/GIF/WebP, at most 1 MiB; logo only with HTML). No logo is selected by default.

Build numbers and asset IDs are operator-provided; review them before sharing a report. Invalid inventory/file errors use controlled descriptions instead of raw input paths or content. Argument-parser usage errors can include the explicit command-line arguments.

## Status and exit policy

The reported selected-component version assessment is separate from its platform/precondition and mitigation dimensions. All local exploitability and reachability fields remain `not_tested`. The tool never emits `likely_exposed` or `unsupported_runtime`.

An affected official bundle is `precondition_present` only when all four operator-reported conditions are present: glibc Linux, enabled SVG decoding, no Node PIE, and an untrusted SVG input path. Missing or conflicting conditions remain unknown. A reported block or PIE produces `mitigated_configuration` while retaining `version_assessment=affected`. Other absent conditions retain `potentially_affected`; they do not establish that the memory bug is absent.

| Exit | Meaning |
| --- | --- |
| `0` | Completed and no enabled gate matched. Unknown evidence does not fail by default. |
| `1` | `--fail-on-finding` matched an affected version, including a mitigated configuration; or `--fail-on-unknown` matched unknown version state or unresolved conditions on an affected version. |
| `2` | Argument/input/output error, hard limit or schema validation failure. |
| `130` | Interrupted; completed assets are preserved with `complete=false` if report publication succeeds. |

A reported fixed component does not fail the unknown gate solely for missing optional platform or configuration evidence. Read the component name: a global result classifies the independently supplied native library, not an installed Sharp package. Repeated interruption or an unwritable output can prevent recovery and is reported through stderr. Once stdout publication starts, interruption can leave a partial document; recovery never appends a second report. A completed publication is not retried.

## Reproducibility

`rules/snapshot.json` is embedded by `tools/build.py`; reports include its canonical SHA-256 (sorted keys, compact JSON, UTF-8 and final newline). `SHA256SUMS` covers the generated single file and source snapshot. Checksums detect differences; they are not publisher signatures. `python tools/build.py --check` verifies both the generated source and release checksums. Runtime assessment never fetches a rule update.

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

CycloneDX component namespaces (`group`) must be text; a nonempty namespace is
not treated as an unscoped Sharp/librsvg identity. Nested components continue to
be traversed independently. Unsupported identity remains unknown coverage.
