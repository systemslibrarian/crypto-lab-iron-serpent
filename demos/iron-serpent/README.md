# Iron Serpent — Serpent-256 Cryptographic Demo

A browser-based cryptographic demo showcasing **Serpent-256**, the AES finalist designed by Eli Biham (Technion, Israel), Ross Anderson (Cambridge), and Lars Knudsen (DTU Denmark).

Part of the [crypto-lab-iron-serpent](https://github.com/systemslibrarian/crypto-lab-iron-serpent) project.

## Live Demo

https://systemslibrarian.github.io/crypto-lab-iron-serpent/

## What the Demo Does

- **Encrypt/Decrypt**: Enter text and a passphrase to encrypt with Serpent-256-CTR, authenticated with HMAC-SHA256 (Encrypt-then-MAC). Payloads can be downloaded as `.json` and loaded back for cross-session round trips
- **Key Derivation**: Argon2id transforms passphrases into 256-bit keys (time=3, mem=64MiB, parallelism=1), with a live passphrase-strength estimate (charset + Diceware word models)
- **Round Visualization**: Animated SVG comparing Serpent's 32 rounds vs AES's 10/12/14 rounds, with attack frontier markers
- **Avalanche Effect**: Flip any single input bit of a 128-bit block and watch ~50% of Serpent's output bits change (Strict Avalanche Criterion)
- **CTR Mode Explorer**: Interactive walkthrough of how a 16-byte block cipher becomes a stream cipher — counter blocks → keystream → XOR, byte by byte. The construction shown is verified byte-for-byte against the real `SerpentCtr` in the test suite
- **Benchmark**: Live Serpent-256-CTR vs AES-256-GCM throughput comparison (MB/s)
- **Attribution**: About section covering the designers, Israeli cryptographic lineage, and AES competition history

## Run Locally

```bash
npm install && npm run dev
```

## Build

```bash
npm run build
```

## Test

```bash
npm test        # unit + a11y (vitest, official AES-submission vectors, axe-core)
npm run test:e2e  # real-browser E2E (Playwright): encrypt/decrypt round trip,
                  # tamper rejection, axe with color-contrast (both themes),
                  # desktop + mobile layout checks
```

## Serpent Implementation Source

**Package**: [`leviathan-crypto`](https://www.npmjs.com/package/leviathan-crypto) v1.4.0
- WASM-based Serpent-256 with bitslice S-boxes
- Zero-dependency WebAssembly cryptography library
- Provides `Serpent` (ECB block), `SerpentCtr` (CTR mode), and authenticated constructions

## Test Vector Sources

Test vectors are sourced from the official AES submission package:
- **Specification**: https://www.cl.cam.ac.uk/~rja14/Papers/serpent.pdf
- **Submission package**: https://www.cl.cam.ac.uk/~rja14/Papers/serpent.tar.gz
- **Vector files used**: `floppy4/ecb_vk.txt` (variable-key) and `floppy4/ecb_vt.txt` (variable-text), KEYSIZE=256 sections

## Architecture

| Layer | Choice |
|---|---|
| Frontend | Vite + TypeScript |
| Cipher | Serpent-256-CTR via `leviathan-crypto` (WASM) |
| KDF | Argon2id via `argon2-browser` (WASM) |
| Authentication | HMAC-SHA256 via Web Crypto API (Encrypt-then-MAC) |
| Benchmark opponent | AES-256-GCM via Web Crypto API |
| UI framework | None — vanilla TypeScript |
