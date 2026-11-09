# Native Xtensa regression inputs

The original 40 standalone BN tests and their fixed inputs were copied only after
checking every input against the successful historical manifest recorded in
`suite_manifest.json`. They include instruction-value oracles, register-window
and exception state checks, hardware loops, native IL/CFG tests and the minimal
same-build WARP roundtrip. The suite is not an exhaustive ISA test and supplies
no DCL recognition precision/recall.

The suite now contains 41 tests. The additional MAC16 validity regression checks
all 1,048,576 MAC16 field combinations, including standalone loads and reserved
slots, and actual native callbacks for rejected encodings. It also checks
non-MAC unknown slots and preserves genuine ILL decoding. Its successful native manifest is recorded separately
under `supplemental_validation` in `suite_manifest.json`; the original fixture
provenance remains intact.

The full-analysis WARP fixture now releases native objects before interpreter
shutdown. Its three cases retain the original IL counts, semantic checks and
WARP GUIDs, with clean native exit0. The original41-test batch and its teardown
warning remain preserved; the changed fixture alone was rerun, as recorded in
`lifecycle_validation` and `fixture_revisions` in the suite manifest. The plugin
payload and the other40 tests are unchanged.

Run from the plugin repository root:

```bash
python3 tools/run_regressions.py \
  --bn-install /absolute/path/binaryninja \
  --bn-license /absolute/path/license.dat \
  --image matteroverwatch-job-runner:latest \
  --output-dir /absolute/path/new-regression-output
```

The launcher checks the packaged file hashes, copies inputs into a new output
directory, exports the current verified plugin and starts the licensed BN runtime
in a network-isolated container. It mounts the license read-only and does not
print its contents. The image must support the supplied BN installation; native
validation currently uses BN6.0.10905. No global BN plugin or settings change is
made. Outputs include the launcher manifest, aggregate log, per-test manifests
and logs, generated BNDB/WARP artifacts and semantic result JSONs.

The `/port` paths in the retained tests refer to this disposable container mount;
they are not required host paths. The raw target/reference ELF fixtures contain
one extracted real `esp_random` function, not complete firmware. GNU dumps and
assembly fixtures are fixed instruction encodings used by value/operand tests.
`baseline_window_exceptions.txt` is the independent earlier window-check model
used by the shared-tail differential checks. Preserve these baseline inputs;
changing them requires a separately reviewed suite-manifest update.
