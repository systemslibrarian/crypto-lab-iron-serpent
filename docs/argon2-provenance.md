# Argon2 source reproduction and distribution evidence

The active path is `demos/iron-serpent/src/kdf.ts` → classic `public/kdf-worker.js` → `public/argon2-bundled.min.js`. The bundle includes WASM. The separate `public/argon2.wasm` is retained distribution material; the worker does not load that standalone file.

`argon2-provenance.json` records both tracked fingerprints and the integrity-pinned official `argon2-browser@1.18.0` npm archive. `python3 scripts/check-argon2-provenance.py` checks local bytes. With `--distribution`, the check downloads that exact archive, validates its SHA-512 integrity, then compares both files byte for byte without extracting archive paths onto disk. Success requires exactly both expected artifacts and their recorded active/retained roles. Missing, empty, duplicate or malformed coverage, unreadable files, missing archive entries and provider errors exit 2. Readable byte/fingerprint or archive-integrity mismatches exit 1. Partial output preserves readable rows and distinguishes attempted from checked artifacts.

Run offline positive and negative controls with:

```sh
python3 -m unittest discover -s scripts/tests -p 'test_argon2_provenance.py' -v
```

Synthetic archive tests exercise both artifact coverage, omitted/duplicate entries, changed bytes, active-role tampering, malformed metadata, timeout, integrity mismatch, archive errors and partial readability. They establish checker behavior, not source provenance. The read-only workflow runs these controls before the live distribution comparison on relevant pull requests and default-branch pushes. It neither deploys the application nor claims upstream source reproduction.

An earlier maintenance inspection established these official distribution matches. The PR workflow repeats that comparison. Distribution identity does not establish upstream C source-to-binary correspondence. On 2026-10-10 the original compiler and reproducible upstream build remained unknown/unverified. App tests and Argon2 known-answer tests would not alone resolve that gap. The source reproduction below is separate evidence. No runtime binary, worker or lab dependency changed.

## Recovered source and clean build diagnostic, 2026-10-10

The official npm version metadata records publisher `gitHead` [63cda65cd2182e39a139aa074e2306332ddd4417](https://github.com/antelle/argon2-browser/tree/63cda65cd2182e39a139aa074e2306332ddd4417), also the target of the official annotated `1.18.0` tag. GitHub reports the tag signature as `no_user`, not a verified signature. The source tree's `argon2` gitlink pins [P-H-C/phc-winner-argon2 at 16d3df698db2486dde480b09a732bf9bf48599f9](https://github.com/P-H-C/phc-winner-argon2/tree/16d3df698db2486dde480b09a732bf9bf48599f9). These are immutable publisher-source candidates, not an attestation connecting the shipped distribution to a C build.

The pinned [CI installer](https://github.com/antelle/argon2-browser/blob/63cda65cd2182e39a139aa074e2306332ddd4417/ci/install.sh#L6) selected Emscripten `latest`; it did not identify an immutable original compiler. The workflow selected Node 16 and the npm publisher metadata reported Node 16.3.0/npm 7.15.1. Neither establishes the original compiler, exact resolved bundle dependencies or build environment.

An isolated source archive build excluded committed `dist` files, copied the exact C submodule, and used an initially empty compiler cache. Unmodified `bash build-wasm.sh` with actual local Emscripten 6.0.10-git and CMake 4.4.3 exited 2: `EXTRA_EXPORTED_RUNTIME_METHODS` is no longer supported. It produced no JS/WASM artifacts. [The saved command report](argon2-source-rebuild-20261010.json) records source-archive hashes, executable identity, stdout/stderr, commands and selected environment. This is a compiler incompatibility diagnostic, not a reproduction or byte mismatch. No original flags were changed to turn the check green.

The bundle has one static WASM base64 payload. Its decoded SHA-256 is `0c2149886c13e4eae4a6ca25ee71d47423c5c8740a874cf04ff816d1b2c901d7` (25,725 bytes), identical to the retained standalone distribution file; the browser still loads the bundle. This establishes byte identity only. To close source correspondence, recover an authenticated reproducing compiler/environment and exact bundler dependency state, clean-build both JS and WASM from the pinned sources, and compare the active bundle and decoded WASM against the shipped bytes. Original compiler and source correspondence remain unknown/unverified; scanner WASM coverage remains partial.

## Reproducing source environment recovered, 2026-10-11

A clean build of those pinned publisher and C sources now reproduces both shipped
artifacts exactly. The selected environment is the official Linux amd64
`emscripten/emsdk` image at immutable digest
`sha256:5871ba43a788243cbf890e2cb1a95e33e9cb72dcf52e1d2077ca39f2171f8b07`.
Its actual compiler reports Emscripten 2.0.23 at
`b15ca40ca02f469de3bf9a4de67a2655aede8974`; its Node/npm versions are
14.15.5/6.14.11. These are measured reproducing versions, **not an assertion that
they were the original publisher environment**. `originalCompiler` remains null.

The exact source `package-lock.json` hash is
`373c51383c37ac3cccdc4d367b347a85b772a9787b95b5ce9596f6d2dfa0ebf2`.
It resolves webpack 5.37.1, webpack-cli 4.7.0 and base64-loader 1.0.0. All seven
Argon2 C objects are freshly compiled with the unchanged upstream build script
and flags; committed distribution files and previous lab objects are excluded.
Compiler-bundled standard libraries are part of the immutable compiler image,
not rebuilt Argon2 inputs. Their complete inventory is unchanged before/after.
Build tools install only into disposable public-upstream scratch with npm
lifecycle scripts disabled. The actual webpack CLI then builds the bundle.

The rebuilt active bundle is 45,921 bytes, SHA-256
`77c64b946baf1a5116dc591f4b9965d636b1b455f75edd2d4a587cb75e01687b`;
the rebuilt WASM is 25,725 bytes, SHA-256
`0c2149886c13e4eae4a6ca25ee71d47423c5c8740a874cf04ff816d1b2c901d7`.
Both are byte-identical to shipped artifacts, including the WASM decoded from
the active bundle. [The actual command report](argon2-source-rebuild-20261011.json)
preserves compiler/image identity, source archives, stdout/stderr, hash comparison
and the two earlier empty-standard-library-cache builds that crashed under amd64
emulation. Those failures are not removed or turned into successes. The first
successful scratch build reported a clock-skew warning while compiling all seven
objects; the reusable checker normalizes source mtimes and requires all seven
compile steps in its actual log.

To repeat, reuse existing clones of the two public upstream repositories with the
recorded commits available, and an existing Docker runtime:

```sh
docker pull --platform linux/amd64 emscripten/emsdk@sha256:5871ba43a788243cbf890e2cb1a95e33e9cb72dcf52e1d2077ca39f2171f8b07
python3 scripts/check-argon2-provenance.py --source-rebuild \
  --publisher-source /path/to/existing/argon2-browser \
  --argon2-source /path/to/existing/phc-winner-argon2
```

For a VM, select its existing `--docker-context` and an existing shared
`--scratch-root`. Each invocation creates its own fresh temporary child. It does
not clone repositories or install lab dependencies. Missing access, absent source
pins/image, unsafe archives, changed source, malformed/incomplete stage output or
missing artifacts exit 2. Readable artifact differences exit 1. Exit 0 requires
the complete source build and all three artifact/active-payload comparisons.
Fingerprint/distribution-only invocations continue reporting source correspondence
as unverified **by that invocation**, even though the separately dated reproduction
is recorded here. The read-only workflow independently rebuilds on relevant PRs
and main pushes; its source job must pass and uploads the full report.

The offline suite also exercises omitted/empty/changed rebuilt bytes, missing or
duplicate active payloads, unsafe paths/links, immutable-source overwrite,
incomplete/malformed stages, failed commands, wrong compiler and missing fresh
compilation. Synthetic matches are checker controls, never build evidence.
Reproducible source correspondence does not establish constant-time behavior or
original build origin. Raw C/WASM scanner coverage remains partial.
