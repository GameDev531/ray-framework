# Vault Docket — vault

Vulnerable→safe patterns for `ray-vault`. Each entry: the class, how it looks
when broken, what makes it safe, and the CWE/catalog tag to stamp. Hunt the
"broken" column; confirm the "safe" column is genuinely present (not just
partially) before dismissing.

## Weak / misused crypto primitives — CWE-327 · A02:2021
- **Broken:** `MD5`/`SHA1` for security; `DES`/`RC4`; AES-ECB; a static or reused
  IV/nonce; unauthenticated encryption (CBC without a MAC); textbook RSA; rolling your
  own crypto.
- **Safe:** AES-GCM/ChaCha20-Poly1305 (AEAD), random per-message nonce, SHA-256+,
  vetted libraries, `argon2`/`scrypt`/`bcrypt`/PBKDF2 for passwords.

## Weak randomness for secrets — CWE-338 · A02:2021
- **Broken:** `Math.random`/`rand()`/`mt_rand` for tokens, keys, nonces, session ids.
- **Safe:** a CSPRNG (`secrets`, `crypto.randomBytes`, `/dev/urandom`).

## Broken key derivation / management — CWE-320
- **Broken:** hardcoded keys/secrets in source (the video's "chave mocada" door);
  keys committed to VCS history; a KDF with no/low iterations or a static salt.
- **Safe:** keys from a secrets manager/env at deploy; per-secret random salt; strong
  KDF parameters. (Hardcoded-secret detection is also ray-cloak's write-time job.)

## Missing encryption at rest — CWE-311 · A02:2021
- **Broken:** credentials, tokens, PII, or payment data stored plaintext; a reversible
  encoding (base64) mistaken for encryption.
- **Safe:** sensitive columns encrypted (or hashed, for verifiers) with managed keys.

## Over-broad datastore privileges — CWE-250
- **Broken:** the app's DB account can `DROP`/`GRANT`/read every tenant/other schemas;
  one connection string with superuser rights.
- **Safe:** least-privilege DB account scoped to the app's tables and operations.

## Failure-opens-crypto — CWE-636
- **Broken:** a `catch` around a decrypt/verify that falls back to plaintext or "allow".
- **Safe:** crypto failure fails closed.

## PQC readiness (advisory)
- Note where long-lived data is protected only by RSA/ECC and would benefit from a
  hybrid/PQC migration plan. Advisory, not a vulnerability by itself.

## What is NOT a finding here

- A fast hash (SHA-256) used for a NON-password integrity check — correct usage.
- Base64 described honestly as encoding, not presented as security.
- A short RSA key in a test fixture (coordinate with ray-magistrate on viability).
- "Not post-quantum" alone, with no other weakness — advisory only.
