# Audit Results: Iron Serpent

Based on a thorough review of the cryptographic pipeline, key derivation, MAC construction, and UI layers, no fundamental security bugs (e.g., canonicalization vulnerabilities, missing verification, broken memory zeroing, or missing domain separation) were identified.  

## Implementation Analysis & Observations

1. **MAC Canonicalization Constraints**
   - **File:** [src/crypto.ts](src/crypto.ts#L100)
   - **Observation:** `macData` is built via `concat(salt, nonce, ciphertextBytes, versionBytes)`. While variable-length fields concatenated without TLV-length prefixes risk canonicalization vulnerabilities, the current construction is inherently bounded and immune.
   - **Evidence:** `assertDecodedLengths` enforces `salt` and `nonce` to precisely 16 bytes each before decryption. Since `versionBytes` is a constant known length appended at the tail, the inner `ciphertextBytes` boundaries remain globally unambiguous.

2. **UI Format Deserialization**
   - **File:** [src/main.ts](src/main.ts#L145)
   - **Observation:** The application offers a 'Hex' payload viewing toggle. If a user manually copies the hex representation of their payload and pastes it into the Decrypt input field, `JSON.parse` will read the structure correctly, but the parsing phase via `fromBase64` (in `decrypt` routine) will fail since hex-encoded elements are not base64 decodeable. This is correctly constrained out of the security layer but represents a mild UX friction edge-case during payload round-trips.

3. **Memory Cleansing Behavior**
   - **File:** [src/kdf.ts](src/kdf.ts#L45) / [public/kdf-worker.js](public/kdf-worker.js#L21)
   - **Observation:** `Uint8Array` components housing plaintexts (`plaintextBytes`, `passphrase`) correctly clear memory by overwriting with zero fills natively inside `finally` blocks and during web worker transit closure operations, thus remaining compliant with secure bounding guidelines.

No corrective refactoring mandates are currently flagged.