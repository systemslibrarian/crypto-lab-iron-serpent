# Iron Serpent — Serpent-256 Cryptographic Demo

A browser-based cryptographic demo showcasing **Serpent-256**, the AES finalist designed by Ross Anderson (Cambridge University, England), Eli Biham (Technion, Haifa, Israel), and Lars Knudsen (University of Bergen, Norway) — affiliations as printed on the 1998 AES submission paper.

Part of the [crypto-lab-iron-serpent](https://github.com/systemslibrarian/crypto-lab-iron-serpent) project.

## Live Demo

https://systemslibrarian.github.io/crypto-lab-iron-serpent/

## What the Demo Does

A password-based authenticated-encryption lab built around the **Serpent** block cipher. It walks you up the concept with a guided **3-step path** — do the encrypt→decrypt round trip, break it with the tamper lab, then unlock the deeper exhibits — so a newcomer meets the pieces in order instead of all at once. Progressive disclosure keeps the advanced panels gated until the core round trip is done.

## Exhibits

1. **Start here (guided tour)**: A numbered path that sequences the lab — round trip → tamper → internals. The analysis panels stay locked until the encrypt→decrypt round trip authenticates, then unlock together
2. **Encrypt/Decrypt**: Enter text and a passphrase to encrypt with Serpent-256-CTR, authenticated with HMAC-SHA256 (Encrypt-then-MAC). Payloads can be downloaded as `.json` and loaded back for cross-session round trips
3. **Key Derivation & separation**: Argon2id transforms passphrases into a 256-bit masterKey (time=3, mem=64MiB, parallelism=1), with a live passphrase-strength estimate; an inline HKDF diagram shows the masterKey fanning into a separate `encKey` and `macKey` and explains why the cipher and the MAC must never share a key
4. **Tamper lab**: Flip one bit of a known-good payload and watch the HMAC refuse to decrypt — verify-then-decrypt, demonstrated rather than asserted
5. **Inside Serpent — the 32 rounds**: Step one 128-bit block through the real Serpent round function (key mixing → 4-bit S-box substitution → linear transform) with a 1..32 counter, spotlight a nibble entering/leaving the S-box, and watch a single flipped input bit avalanche across the block. Every value comes from a spec-accurate Serpent verified byte-for-byte against the official AES vectors and the production WASM engine
6. **Security Margin**: Reduced-round attack frontier vs full round count — read as a margin, not a countdown
7. **Avalanche Effect**: Flip any single input bit of a 128-bit block and watch ~50% of Serpent's output bits change (Strict Avalanche Criterion). Type ASCII or enter hex; the flipped input bit is highlighted on the block
8. **CTR Mode Explorer**: Interactive walkthrough of how a 16-byte block cipher becomes a stream cipher — counter blocks → keystream → XOR, byte by byte — plus a live **nonce-reuse** footgun showing `CT1 ⊕ CT2 = PT1 ⊕ PT2`. Verified byte-for-byte against the real `SerpentCtr` in the test suite
9. **Benchmark**: Live Serpent-256-CTR vs AES-256-GCM throughput (MB/s), with a takeaway banner: slower here = more rounds + no hardware AES-NI, **not** weaker
10. **Attribution**: About section covering the designers, Israeli cryptographic lineage, and AES competition history

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
