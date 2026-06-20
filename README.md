# iron-serpent

## What It Is

Iron Serpent is a browser demo for password-based symmetric encryption built around Serpent-256-CTR, with Argon2id deriving the key material from a passphrase and HMAC-SHA256 authenticating the payload. It shows how to encrypt and decrypt text in the browser without sending plaintext to a server. The problem it addresses is confidential, integrity-checked handling of user-supplied text behind a shared secret. The security model is symmetric authenticated encryption with a password-derived key.

## When to Use It

- Use it for client-side text encryption demos that need to show a non-AES block cipher in a real browser workflow. Serpent-256-CTR gives you a concrete symmetric cipher example while Argon2id and HMAC-SHA256 show the surrounding pieces needed for password-based authenticated encryption.
- Use it for teaching or lab work around conservative block-cipher design choices. The demo contrasts Serpent's 32-round design and benchmark behavior with AES-256-GCM in a way that is easy to inspect locally.
- Use it when you need a passphrase-derived workflow instead of raw random keys. Argon2id makes the demo appropriate for explaining how human-entered secrets can be stretched into a 256-bit encryption key.
- Do not use it when you need a standardized interchange format or protocol integration. The JSON payload and demo wiring are suitable for a lab environment, not a substitute for established application protocols.

## Live Demo

[https://systemslibrarian.github.io/crypto-lab-iron-serpent/](https://systemslibrarian.github.io/crypto-lab-iron-serpent/)

The live demo lets you enter a passphrase and plaintext, produce an encrypted JSON payload, and decrypt that payload back in the browser. A **Load example** button seeds a sample message, and **Send this payload to Decrypt** wires the encrypt output straight into the decrypt panel for a one-click round trip. It also includes Base64 and Hex output controls, a benchmark panel with Data size and Iterations controls, an Argon2id parameters panel that shows the KDF settings used for key derivation, a security-margin visualization, and an interactive **Avalanche Effect** panel that flips a single input bit and shows how ~50% of Serpent-256's output bits change (the Strict Avalanche Criterion).

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-iron-serpent.git
cd crypto-lab-iron-serpent/demos/iron-serpent
npm install
npm run dev
```

No environment variables are required.

Run the test suite (Serpent-256 official AES test vectors, CTR round-trips, tamper detection, KDF/HMAC, the avalanche property, and automated axe-core accessibility checks) with:

```bash
npm test
```

## Part of the Crypto-Lab Suite

This demo is one part of the broader Crypto-Lab collection at [https://systemslibrarian.github.io/crypto-lab/](https://systemslibrarian.github.io/crypto-lab/).
