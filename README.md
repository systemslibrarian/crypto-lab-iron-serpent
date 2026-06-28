# crypto-lab-iron-serpent

## What It Is

Iron Serpent is a browser demo for password-based symmetric encryption built around Serpent-256-CTR, with Argon2id deriving the key material from a passphrase and HMAC-SHA256 authenticating the payload. It shows how to encrypt and decrypt text in the browser without sending plaintext to a server. The problem it addresses is confidential, integrity-checked handling of user-supplied text behind a shared secret. The security model is symmetric authenticated encryption with a password-derived key.

## When to Use It

- Use it for client-side text encryption demos that need to show a non-AES block cipher in a real browser workflow. Serpent-256-CTR gives you a concrete symmetric cipher example while Argon2id and HMAC-SHA256 show the surrounding pieces needed for password-based authenticated encryption.
- Use it for teaching or lab work around conservative block-cipher design choices. The demo contrasts Serpent's 32-round design and benchmark behavior with AES-256-GCM in a way that is easy to inspect locally.
- Use it when you need a passphrase-derived workflow instead of raw random keys. Argon2id makes the demo appropriate for explaining how human-entered secrets can be stretched into a 256-bit encryption key.
- Do NOT use it for real data protection or as a standardized interchange format. The JSON payload and demo wiring are suitable for a lab environment, not a substitute for established, audited application protocols.

## Live Demo

**[systemslibrarian.github.io/crypto-lab-iron-serpent](https://systemslibrarian.github.io/crypto-lab-iron-serpent/)**

The live demo lets you enter a passphrase and plaintext, produce an encrypted JSON payload, and decrypt that payload back in the browser. A **Load example** button seeds a sample message, and **Send this payload to Decrypt** wires the encrypt output straight into the decrypt panel for a one-click round trip. It also includes Base64 and Hex output controls, a benchmark panel with Data size and Iterations controls, an Argon2id parameters panel that shows the KDF settings used for key derivation, a security-margin visualization, and an interactive **Avalanche Effect** panel that flips a single input bit and shows how ~50% of Serpent-256's output bits change (the Strict Avalanche Criterion).

## What Can Go Wrong

- CTR mode provides no integrity on its own. Skipping or mis-ordering the HMAC check lets an attacker flip ciphertext bits and silently flip the corresponding plaintext bits.
- Counter/nonce reuse under the same key is catastrophic in CTR. XORing two ciphertexts produced with the same keystream recovers the keystream and both plaintexts.
- Weak Argon2id parameters undermine everything. Low memory or iteration counts make passphrase-derived keys cheap to brute-force offline, regardless of how strong Serpent is.
- Verify-then-decrypt matters. Checking the HMAC before decrypting (encrypt-then-MAC) avoids feeding attacker-controlled ciphertext into the cipher.
- A larger cipher security margin does not fix protocol mistakes. The usual breaks come from mode, nonce, KDF, or MAC errors, not from the Serpent block cipher itself.

## Real-World Usage

- Serpent was an AES finalist (1998), placing second to Rijndael; it is valued for its conservative 32-round design and large security margin.
- Serpent ships in disk-encryption tools such as VeraCrypt (and the former TrueCrypt), including cascade modes that chain it with AES and Twofish.
- Argon2id is the recommended password-hashing/KDF function (Password Hashing Competition winner) for stretching passphrases into encryption keys.
- HMAC-SHA-256 is a widely standardized MAC used to authenticate ciphertexts in encrypt-then-MAC constructions across many protocols.

## How to Run Locally

```bash
git clone https://github.com/systemslibrarian/crypto-lab-iron-serpent
cd crypto-lab-iron-serpent/demos/iron-serpent
npm install
npm run dev
```

## Related Demos

- [crypto-lab-aes-modes](https://systemslibrarian.github.io/crypto-lab-aes-modes/) — AES-GCM/CBC authenticated encryption, the standard cipher Serpent is compared against.
- [crypto-lab-world-ciphers](https://systemslibrarian.github.io/crypto-lab-world-ciphers/) — Camellia, ARIA, SM4, and Kuznyechik, other national/non-AES block ciphers.
- [crypto-lab-chacha20-stream](https://systemslibrarian.github.io/crypto-lab-chacha20-stream/) — ChaCha20 keystream generation, the same XOR-keystream danger (nonce reuse) as CTR.
- [crypto-lab-shadow-vault](https://systemslibrarian.github.io/crypto-lab-shadow-vault/) — Argon2id + ChaCha20-Poly1305 password-based encryption, the same workflow with an AEAD cipher.
- [crypto-lab-kdf-arena](https://systemslibrarian.github.io/crypto-lab-kdf-arena/) — Argon2id, scrypt, PBKDF2, and HKDF compared, the key-derivation step this demo relies on.

## Testing

Run the test suite (Serpent-256 official AES test vectors, CTR round-trips, tamper detection, KDF/HMAC, the avalanche property, and automated axe-core accessibility checks) with:

```bash
npm test
```

---

*One of 60+ browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
