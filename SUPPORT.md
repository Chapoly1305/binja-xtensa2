# Validated support boundaries

The plugin derives from nicabi/binja-xtensa2 and retains the MIT license.
The verified payload is recorded in `manifest.json`; file hashes cover the
plugin, license, metadata and analysis configuration. This source identity is
unchanged by moving it to this repository.

The decoder handles 2/3-byte instructions. Targeted tests cover repaired integer
operations, register-window calls and exception state, hardware loops,
exception returns, vector/DEPC configuration, MAC16 validity and native WARP
roundtrips. The native suite contains 41 tests, validated with Binary Ninja
6.0.10905. Its retained input hashes and validation provenance are recorded in
`regressions/xtensa/suite_manifest.json`.

Six controlled same-build reference/stripped-target experiments cover ESP32 and
ESP32-S3 lighting applications at Matter 1.4, 1.4.2 and 1.5. Aggregate raw-name
recall was 59528/63302; assessed precision was 59528/59538. Another 36 matched
starts lacked symbol truth. These are same-build raw-symbol controls, not
cross-application or deployed-firmware recognition accuracy.

The original ESP32-S3 1.4.2 native exit139 remains unexplained despite a successful
recovery. Repeated exports from saved databases are stable; two ESP32-S3
functions have different constraints across fresh analyses. Do not claim full
ISA semantics, universal native stability or fresh-analysis determinism.

Remaining boundaries include optional/configuration-dependent instructions,
ESP32-S3 extensions, generic memory faults, cross-function hardware loops,
nonstandard ENTRY operands and physical interprocedural register rotation.
Cache/TLB intrinsics model contracts, not complete hardware behavior.

The MatterOverwatch repository owns pipeline integration, corpus packaging,
reference selection and the detailed evidence inventory. Local workdir evidence
paths in retained fixture manifests refer to that original validation workspace;
the source repository does not include full firmware, BN licenses or analysis
databases. Standalone native suite reproduction uses `tools/run_regressions.py`.
