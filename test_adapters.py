"""Synthetic ELF/package/source evidence. No native code or SVG is executed."""
import contextlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import sharp_rsvg_rce_check as c


def elf_fixture(bits=64, endian="<", kind=3, interpreter=b"/lib64/ld-linux-x86-64.so.2\0"):
    ident = b"\x7fELF" + bytes([1 if bits == 32 else 2, 1 if endian == "<" else 2, 1]) + b"\0" * 9
    size, phsize = (52, 32) if bits == 32 else (64, 56)
    count = int(interpreter is not None)
    fmt = "HHIIIIIHHHHHH" if bits == 32 else "HHIQQQIHHHHHH"
    header = struct.pack(endian + fmt, kind, 3 if bits == 32 else 62, 1, 0, size, 0, 0, size, phsize, count, 0, 0, 0)
    program = b""
    if interpreter is not None:
        offset = size + phsize
        fields = (3, offset, 0, 0, len(interpreter), len(interpreter), 4, 1) if bits == 32 else (3, 4, offset, 0, 0, len(interpreter), len(interpreter), 1)
        program = struct.pack(endian + ("IIIIIIII" if bits == 32 else "IIQQQQQQ"), *fields) + interpreter
    return ident + header + program


class AdapterTests(unittest.TestCase):
    def cli(self, *args):
        with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
            code = c.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_cyclonedx_namespace_does_not_become_unscoped_package(self):
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/"bom.json"
            data=dict(bomFormat="CycloneDX",specVersion="1.6",components=[dict(group="@vendor",name="sharp",version="0.35.4",components=[dict(name="sharp",version="0.35.5")])])
            path.write_text(json.dumps(data),encoding="utf-8")
            rows=c.metadata_results(path,Path(directory),"sbom","subject")
            self.assertEqual(["0.35.5"],[row["component"]["version"] for row in rows])
            data["components"][0]["group"]=[]
            path.write_text(json.dumps(data),encoding="utf-8")
            with self.assertRaises(c.ContractError):c.metadata_results(path,Path(directory),"sbom","subject")

    def test_arrow_return_regex_body_is_opaque(self):
        tokens = c._js_tokens("const pattern = () => /const image = require('sharp'); image(input)/;")
        self.assertIn("@regex", [value for value, _ in tokens])
        self.assertNotIn("require", [value for value, _ in tokens])

    def test_elf32_64_endianness_and_loader_hints_never_establish_mitigation(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "node.elf"
            for bits in [32, 64]:
                for endian in ["<", ">"]:
                    for kind, interpreter, layout, libc in [
                        (3, b"/lib/ld-linux.so.2\0", "dynamic_executable_candidate", "glibc_loader_candidate"),
                        (2, b"/lib/ld-musl-x86_64.so.1\0", "fixed_address_executable_candidate", "musl_loader_candidate"),
                        (3, None, "shared_or_static_pie_unknown", "unknown"),
                    ]:
                        path.write_bytes(elf_fixture(bits, endian, kind, interpreter))
                        result = c.inspect_elf(path)
                        self.assertEqual((bits, layout, libc), (result["class"], result["layout"], result["libc"]))
                        code, out, err = self.cli("--node-elf", str(path), "--evidence-root", directory)
                        self.assertEqual((0, ""), (code, err))
                        row = json.loads(out)["results"][0]
                        self.assertEqual("unknown", row["status"])
                        self.assertEqual("unknown", row["mitigation"]["state"])
                        self.assertEqual("not_tested", row["exploitability"])
                        self.assertNotIn(directory, out)
                        self.assertNotIn("/lib/ld-", out)

    def test_malformed_and_excessive_elf_headers_reject_before_output(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.elf"
            cases = [b"", b"not ELF", elf_fixture()[:50], elf_fixture()[:-1], elf_fixture(interpreter=b"no-null")]
            base = bytearray(elf_fixture())
            excessive = bytearray(base)
            struct.pack_into("<H", excessive, 56, 65535)
            cases.append(bytes(excessive))
            bad_offset = bytearray(base)
            struct.pack_into("<Q", bad_offset, 32, 2**64 - 1)
            cases.append(bytes(bad_offset))
            bad_entry_size = bytearray(base)
            struct.pack_into("<H", bad_entry_size, 54, 8)
            cases.append(bytes(bad_entry_size))
            bad_segment = bytearray(base)
            struct.pack_into("<Q", bad_segment, 72, 2**63)
            cases.append(bytes(bad_segment))
            repeated = bytearray(elf_fixture()[:64])
            struct.pack_into("<H", repeated, 56, 2)
            loader = b"/lib/ld-linux.so.2\0"
            ph = struct.pack("<IIQQQQQQ", 3, 4, 176, 0, 0, len(loader), len(loader), 1)
            cases.append(bytes(repeated) + ph + ph + loader)
            for data in cases:
                path.write_bytes(data)
                code, out, _ = self.cli("--node-elf", str(path), "--evidence-root", directory)
                self.assertEqual((2, ""), (code, out))
            # A no-program-header ELF must not seek to an arbitrary offset.
            no_headers = bytearray(elf_fixture(interpreter=None))
            struct.pack_into("<Q", no_headers, 32, 2**64 - 1)
            path.write_bytes(no_headers)
            self.assertEqual("shared_or_static_pie_unknown", c.inspect_elf(path)["layout"])

    def test_elf_unused_null_segments_and_file_open_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.elf"
            raw = bytearray(elf_fixture())
            struct.pack_into("<I", raw, 64, 0)
            struct.pack_into("<Q", raw, 72, 2**64 - 1)
            path.write_bytes(raw)
            self.assertEqual("shared_or_static_pie_unknown", c.inspect_elf(path)["layout"])
            real_open = os.open
            def changed_input(*args, **kwargs):
                replacement = path.with_suffix(".new")
                replacement.write_bytes(elf_fixture())
                os.replace(replacement, path)
                return real_open(*args, **kwargs)
            with mock.patch.object(c.os, "open", side_effect=changed_input):
                with self.assertRaises(c.ContractError): c.inspect_elf(path)
            with mock.patch.object(c.os, "open", side_effect=AssertionError("must reject before open")):
                with self.assertRaises(c.ContractError): c.inspect_elf(Path(directory))

    def test_npm_lock_versions_transitive_and_link_uncertainty(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock.json"
            for lv in [1, 2, 3]:
                data = {"lockfileVersion": lv}
                if lv == 1:
                    data["dependencies"] = {"parent": {"dependencies": {"sharp": {"version": "0.35.4"}}}}
                else:
                    data["packages"] = {"node_modules/parent/node_modules/sharp": {"version": "0.35.4", "resolved": "https://PRIVATE-SYNTHETIC.invalid"}}
                path.write_text(json.dumps(data), encoding="utf-8")
                code, out, _ = self.cli("--npm-lock", str(path), "--evidence-root", directory)
                self.assertEqual(0, code)
                row = json.loads(out)["results"][0]
                self.assertEqual("0.35.4", row["component"]["version"])
                self.assertEqual("unknown", row["status"])
                self.assertNotIn("PRIVATE-SYNTHETIC", out)
            path.write_text('{"lockfileVersion":3,"packages":{"node_modules/sharp":{"version":"0.35.5","link":true}}}', encoding="utf-8")
            _, out, _ = self.cli("--npm-lock", str(path), "--evidence-root", directory)
            self.assertIsNone(json.loads(out)["results"][0]["component"]["version"])
            path.write_text('{"lockfileVersion":3,"packages":{"node_modules/sharp":{"version":"0.35.5","link":0}}}', encoding="utf-8")
            self.assertEqual(2, self.cli("--npm-lock", str(path), "--evidence-root", directory)[0])
            path.write_text('{"lockfileVersion":1,"dependencies":{"image":{"version":"npm:sharp@0.35.4"}}}', encoding="utf-8")
            code, out, _ = self.cli("--npm-lock", str(path), "--evidence-root", directory)
            row = json.loads(out)["results"][0]
            self.assertEqual(0, code)
            self.assertEqual("Sharp package metadata", row["component"]["name"])
            self.assertIsNone(row["component"]["version"])
            self.assertEqual("unknown", row["status"])

    def test_cyclonedx_spdx_and_uncovered_metadata_never_infer_selection(self):
        fixtures = [
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": "sharp", "version": "0.35.5", "components": [{"name": "librsvg", "version": "2.63.2"}]}]},
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": {"name": "sharp", "version": "0.35.5", "components": [{"name": "librsvg", "version": "2.63.2"}]}}},
            {"spdxVersion": "SPDX-2.3", "packages": [{"name": "sharp", "versionInfo": "0.35.5"}, {"name": "librsvg", "versionInfo": "2.63.2"}]},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bom.json"
            for data in fixtures:
                path.write_text(json.dumps(data), encoding="utf-8")
                code, out, _ = self.cli("--sbom", str(path), "--evidence-root", directory)
                self.assertEqual(0, code)
                rows = json.loads(out)["results"]
                self.assertEqual(2, len(rows))
                self.assertEqual({"unknown"}, {r["status"] for r in rows})
            path.write_text('{"bomFormat":"CycloneDX","specVersion":"1.6","components":[]}', encoding="utf-8")
            _, out, _ = self.cli("--sbom", str(path), "--evidence-root", directory)
            self.assertEqual("unknown", json.loads(out)["results"][0]["evidence"][0]["state"])

    def test_malformed_sbom_versions_and_names_are_controlled_input_errors(self):
        cases = [
            {"bomFormat": "CycloneDX", "specVersion": []},
            {"spdxVersion": {}},
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": []}]},
            {"spdxVersion": "SPDX-2.3", "packages": [{"name": {}}]},
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "metadata": {"component": []}},
            {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"name": "sharp", "version": []}]},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bom.json"
            for data in cases:
                path.write_text(json.dumps(data), encoding="utf-8")
                code, out, err = self.cli("--sbom", str(path), "--evidence-root", directory)
                self.assertEqual((2, ""), (code, out))
                self.assertNotIn("Traceback", err)

    def test_source_decode_block_and_unblock_are_only_candidates(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input.ts"
            path.write_text("import image from 'sharp';\nimage.block({operation:['VipsForeignLoadSvg']});\nimage(untrustedInput); image.unblock(options);", encoding="utf-8")
            code, out, _ = self.cli("--source", str(path), "--evidence-root", directory)
            self.assertEqual(0, code)
            row = json.loads(out)["results"][0]
            self.assertEqual(3, len(row["evidence"]))
            self.assertEqual({"candidate"}, {e["state"] for e in row["evidence"]})
            self.assertEqual("unknown", row["mitigation"]["state"])
            self.assertEqual([2, 3, 3], [e["line"] for e in row["evidence"]])
            for text in ["// sharp(input);", "const text=\"require('sharp'); image(input)\";", "import image from 'other'; image(input);"]:
                path.write_text(text, encoding="utf-8")
                _, out, _ = self.cli("--source", str(path), "--evidence-root", directory)
                self.assertEqual("unknown", json.loads(out)["results"][0]["evidence"][0]["state"])
            for separator in ["\r", "\r\n", "\u2028", "\u2029"]:
                path.write_bytes(("// comment" + separator + "import image from 'sharp';" + separator + "image(input);").encode("utf-8"))
                _, out, _ = self.cli("--source", str(path), "--evidence-root", directory)
                evidence = json.loads(out)["results"][0]["evidence"][0]
                self.assertEqual(("candidate", 3), (evidence["state"], evidence["line"]))

    def test_all_adapter_inputs_are_protected_even_with_force_and_no_execution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "source.js"
            path.write_text("process.exit(99);", encoding="utf-8")
            args = ["--source", str(path), "--evidence-root", directory]
            self.assertEqual(2, self.cli(*args, "--output", str(path), "--force")[0])
            alias = root / "alias.js"
            os.link(path, alias)
            self.assertEqual(2, self.cli(*args, "--output", str(alias), "--force")[0])
            self.assertEqual(2, self.cli("--source", str(path))[0])
            with mock.patch.object(subprocess, "run", side_effect=AssertionError("no execution")):
                self.assertEqual(0, self.cli(*args)[0])

    def test_adapters_preserve_report_contract_and_standalone_distribution(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.js"
            source.write_text("const image=require('sharp'); image(input);", encoding="utf-8")
            args = ["--source", str(source), "--evidence-root", directory]
            for fmt in ["json", "csv", "html"]:
                code, out, _ = self.cli(*args, "--format", fmt)
                self.assertEqual(0, code)
                self.assertIn("source.js", out)
                self.assertNotIn(directory, out)
            checker = root / "checker.py"
            checker.write_bytes(Path(c.__file__).read_bytes())
            result = subprocess.run([sys.executable, str(checker), *args], capture_output=True, text=True, check=True)
            self.assertEqual("candidate", json.loads(result.stdout)["results"][0]["evidence"][0]["state"])


if __name__ == "__main__":
    unittest.main()
