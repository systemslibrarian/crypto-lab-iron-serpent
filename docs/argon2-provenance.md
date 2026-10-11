# Argon2 distribution evidence

The active path is `demos/iron-serpent/src/kdf.ts` → classic `public/kdf-worker.js` → `public/argon2-bundled.min.js`. The bundle includes WASM. The separate `public/argon2.wasm` is retained distribution material; the worker does not load that standalone file.

`argon2-provenance.json` records both tracked fingerprints and the integrity-pinned official `argon2-browser@1.18.0` npm archive. `python3 scripts/check-argon2-provenance.py` checks local bytes. With `--distribution`, the check downloads that exact archive, validates its SHA-512 integrity, then compares both files byte for byte without extracting archive paths onto disk. Success requires exactly both expected artifacts and their recorded active/retained roles. Missing, empty, duplicate or malformed coverage, unreadable files, missing archive entries and provider errors exit 2. Readable byte/fingerprint or archive-integrity mismatches exit 1. Partial output preserves readable rows and distinguishes attempted from checked artifacts.

Run offline positive and negative controls with:

```sh
python3 -m unittest discover -s scripts/tests -p 'test_argon2_provenance.py' -v
```

Synthetic archive tests exercise both artifact coverage, omitted/duplicate entries, changed bytes, active-role tampering, malformed metadata, timeout, integrity mismatch, archive errors and partial readability. They establish checker behavior, not source provenance. The read-only workflow runs these controls before the live distribution comparison on relevant pull requests and default-branch pushes. It neither deploys the application nor claims upstream source reproduction.

An earlier maintenance inspection established these official distribution matches. The PR workflow repeats that comparison. Distribution identity does not establish upstream C source-to-binary correspondence. The original compiler and reproducible upstream build remain unknown/unverified. App tests and Argon2 known-answer tests would not alone resolve that gap. No binary, worker, dependency or deployment change is included.

## Recovered source and clean build diagnostic, 2026-10-10

The official npm version metadata records publisher `gitHead` [63cda65cd2182e39a139aa074e2306332ddd4417](https://github.com/antelle/argon2-browser/tree/63cda65cd2182e39a139aa074e2306332ddd4417), also the target of the official annotated `1.18.0` tag. GitHub reports the tag signature as `no_user`, not a verified signature. The source tree's `argon2` gitlink pins [P-H-C/phc-winner-argon2 at 16d3df698db2486dde480b09a732bf9bf48599f9](https://github.com/P-H-C/phc-winner-argon2/tree/16d3df698db2486dde480b09a732bf9bf48599f9). These are immutable publisher-source candidates, not an attestation connecting the shipped distribution to a C build.

The pinned [CI installer](https://github.com/antelle/argon2-browser/blob/63cda65cd2182e39a139aa074e2306332ddd4417/ci/install.sh#L6) selected Emscripten `latest`; it did not identify an immutable original compiler. The workflow selected Node 16 and the npm publisher metadata reported Node 16.3.0/npm 7.15.1. Neither establishes the original compiler, exact resolved bundle dependencies or build environment.

An isolated source archive build excluded committed `dist` files, copied the exact C submodule, and used an initially empty compiler cache. Unmodified `bash build-wasm.sh` with actual local Emscripten 6.0.10-git and CMake 4.4.3 exited 2: `EXTRA_EXPORTED_RUNTIME_METHODS` is no longer supported. It produced no JS/WASM artifacts. [The saved command report](argon2-source-rebuild-20261010.json) records source-archive hashes, executable identity, stdout/stderr, commands and selected environment. This is a compiler incompatibility diagnostic, not a reproduction or byte mismatch. No original flags were changed to turn the check green.

The bundle has one static WASM base64 payload. Its decoded SHA-256 is `0c2149886c13e4eae4a6ca25ee71d47423c5c8740a874cf04ff816d1b2c901d7` (25,725 bytes), identical to the retained standalone distribution file; the browser still loads the bundle. This establishes byte identity only. To close source correspondence, recover an authenticated reproducing compiler/environment and exact bundler dependency state, clean-build both JS and WASM from the pinned sources, and compare the active bundle and decoded WASM against the shipped bytes. Original compiler and source correspondence remain unknown/unverified; scanner WASM coverage remains partial.
