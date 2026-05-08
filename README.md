# tells-encryption-spec

> Public specification of the at-rest encryption used by [tells](https://tells.voiddo.com) — text-first analysis for what people leave unsaid.

This repository documents — exactly — the cryptographic primitives that
protect tells user data at rest. It is published so privacy-conscious users,
practitioners, journalists, and security researchers can verify our claims
without needing access to the application source.

The implementation lives in the (private) tells backend. This repo is the
spec; the spec is the contract.

## Why publish the spec, not the code

We split the privacy surface from the business surface:

- **Public** — security primitives, prompt templates, cultural framing files.
- **Private** — backend application code, database schemas, business logic.

You can audit what we promise; we keep what we built. This repo is one of the
three public privacy components:

- [voidd0/tells-encryption-spec](https://github.com/voidd0/tells-encryption-spec) — this repo.
- [voidd0/tells-prompt-templates](https://github.com/voidd0/tells-prompt-templates) — the public prompt contracts behind tells analysis.
- [voidd0/tells-cultural-framing](https://github.com/voidd0/tells-cultural-framing) — per-language framing layer.

## Specification — version 1.0 (effective 2 May 2026)

### 1. Algorithm

**AES-256-GCM** (authenticated encryption with additional data, AEAD).

- 256-bit key → AES-256 block cipher
- 96-bit nonce → mandatory GCM mode parameter
- 128-bit auth tag → tamper detection

GCM was chosen over alternatives (XChaCha20-Poly1305, ChaCha20-Poly1305) for
ecosystem maturity, native AES-NI hardware acceleration on the production VPS,
and the Python `cryptography` library's `AESGCM` wrapper exposing exactly the
contract we need.

### 2. Master encryption key

The master key is a single 32-byte (256-bit) value stored in the
`MASTER_ENCRYPTION_KEY` environment variable on the production server.

**Storage rules:**

- Stored in the env var only.
- **Never** persisted to the database.
- **Never** committed to any repository (this one or the private backend).
- **Never** logged.
- Backed up out-of-band by the operator only.

If both the database and the master key were leaked simultaneously, encrypted
data would be decryptable. The threat model (see
[tells.voiddo.com/legal/threat-model](https://tells.voiddo.com/legal/threat-model))
explicitly addresses this: an attacker needs both.

### 3. Per-user key derivation — HKDF-SHA256

Each user has their own 32-byte AES key, **derived from** the master key:

```
per_user_key = HKDF-SHA256(
    ikm  = master_key,                # 32 bytes from env var
    salt = utf8(user_uuid),           # canonical lowercase UUID string
    info = b"tells:patterns:user-key:v1",
    length = 32,
)
```

Derivation is deterministic: given the same master key and the same user UUID,
the same per-user key is produced. This means we never store per-user keys —
they are recomputed when needed and discarded.

The `info` string namespaces the derivation to the per-user-patterns purpose;
future derivations for unrelated purposes get distinct `info` strings so
key separation is preserved.

### 4. AAD — Additional Authenticated Data

Every ciphertext binds three context fields via AES-GCM's AAD parameter:

```
aad_dict = sorted({
    "u": str(user_id),
    "p": str(tracked_person_id),    # if applicable
    "t": iso_8601(created_at),       # if applicable
})
aad_bytes = utf8(json_dumps(aad_dict, sort_keys=True, separators=(',', ':')))
```

AAD is supplied at encryption time and **must be reconstructed identically**
at decryption time — if any field has drifted, the GCM auth check fails and
decryption raises `InvalidTag`.

This protects against:

- **Cross-user ciphertext shuffling** — an attacker swapping rows between
  users. The user_id in AAD changes; auth check fails.
- **Tracked-person re-pointing** — re-attributing one subject's snapshot to
  a different subject within the same user.
- **Timestamp spoofing** — re-dating a snapshot to look fresher or older.

### 5. Nonce

Every encryption operation generates a fresh **12-byte (96-bit) random nonce**
via `os.urandom(12)`. Nonces are never reused under the same key.

The output ciphertext is the URL-safe base64 of `nonce(12) || ciphertext_with_tag`.

### 6. Storage envelope

Encrypted JSON payloads are wrapped in a versioned envelope so the
plaintext-mode and encrypted-mode storage rows share the same JSONB column
shape:

```json
{ "_enc": "<urlsafe-base64 nonce + ciphertext + tag>", "_v": 2 }
```

- `_v: 2` — the AAD-bound, per-user-key envelope (this spec).
- `_v: 1` (or absent) — legacy envelope using the master key directly. Read
  path falls back to the legacy decryption automatically; new writes use v2.

Plaintext rows (no opt-in, or pre-opt-in legacy data) hold the raw JSON value
and are returned as-is by the decrypt path.

### 7. Master key rotation

The master key may be rotated on a 90-day cadence. Rotation is performed by:

1. Generating a new 32-byte master key.
2. Walking every encrypted row.
3. Decrypting each row's ciphertext under the **old** master.
4. Re-deriving the per-user key under the **new** master.
5. Re-encrypting under the new per-user key, preserving the same AAD.
6. Writing the new envelope back.

Once all rows have been re-encrypted, the old master is destroyed.

The rotation orchestrator is storage-agnostic: it accepts an iterable of
`(descriptor, envelope, context, write_back)` tuples so the caller drives DB
iteration. Counters returned: `{rotated, skipped_plain, v1_legacy}`.

### 8. Cryptographic deletion (GDPR Article 17)

When a user requests account deletion, the per-user HKDF salt — the user UUID
itself — is destroyed by the user-row hard-delete. Without the salt,
`derive_user_key` cannot reproduce the original per-user key. Any retained
ciphertext (e.g. in a backup) becomes unrecoverable.

The deletion audit log records:

- The deletion timestamp.
- The SHA-256 fingerprint of the destroyed user UUID — non-reversible, but
  stable enough that a future audit can verify the deletion took place if the
  same UUID surfaces in a backup.
- The crypto scheme: `"HKDF-SHA256 + AES-256-GCM"`.

The user UUID itself is **never** retained in the audit log.

### 9. Out of scope (v1)

This spec defends against the eight threats enumerated in the
[tells threat model](https://tells.voiddo.com/legal/threat-model). It does
**not** defend against:

- Government-level adversaries (NSA-class actors).
- Compromise of the upstream model provider at provider level.
- Side-channel attacks on model-provider response timing.
- Hardware-level extraction of the master key from the VPS.

If your threat model includes any of the above, tells is not the right tool.

### 10. Audit path

Within 90 days of public launch, an external freelance security auditor
verifies this spec against the running backend. The audit report will be
published at `tells.voiddo.com/legal/audit-2026.html`. Subsequent annual
audits maintain the trust signal.

## Reporting issues

Cryptographic concerns: open an issue on this repo, or email
[hi@voiddo.com](mailto:hi@voiddo.com). Disclosure SLAs: 48-hour
acknowledgement, 14-day fix-or-explain, public diff to this spec when the
implementation changes.

## License

MIT — see [LICENSE](LICENSE).

---

Built by [vøiddo](https://voiddo.com/) — a small studio shipping AI-flavoured products, free dev tools, Chrome extensions and weird browser games.
