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

A reported fixed component does not fail the unknown gate solely for missing optional platform or configuration evidence. Read the component name: a global result classifies the independently supplied native library, not an installed Sharp package. Repeated interruption or an unwritable output can prevent recovery and is reported through stderr.

## Reproducibility

`rules/snapshot.json` is embedded by `tools/build.py`; reports include its canonical SHA-256 (sorted keys, compact JSON, UTF-8 and final newline). `SHA256SUMS` covers the generated single file and source snapshot. Checksums detect differences; they are not publisher signatures. `python tools/build.py --check` verifies both the generated source and release checksums. Runtime assessment never fetches a rule update.
