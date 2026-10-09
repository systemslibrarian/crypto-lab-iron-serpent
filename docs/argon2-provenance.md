# Argon2 distribution evidence

The active path is `demos/iron-serpent/src/kdf.ts` → classic `public/kdf-worker.js` → `public/argon2-bundled.min.js`. The bundle includes WASM. The separate `public/argon2.wasm` is retained distribution material; the worker does not load that standalone file.

`argon2-provenance.json` records both tracked fingerprints and the integrity-pinned official `argon2-browser@1.18.0` npm archive. `python3 scripts/check-argon2-provenance.py` checks local bytes. With `--distribution`, the check downloads that exact archive, validates its SHA-512 integrity, then compares both files byte for byte without extracting archive paths onto disk. Unreadable distribution exits 2; a byte/fingerprint mismatch exits 1.

An earlier maintenance inspection established these official distribution matches. The PR workflow repeats that comparison. Distribution identity does not establish upstream C source-to-binary correspondence. The original compiler and reproducible upstream build remain unknown/unverified. App tests and Argon2 known-answer tests would not alone resolve that gap. No binary, worker, dependency or deployment change is included.
