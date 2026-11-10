# ADR-0030: Reject recognizable file headers on client chunk uploads

- **Status:** Proposed
- **Date:** 2026-11-10
- **Decision owners:** mickvandijke
- **Reviewers:** Node and client maintainers, pending review
- **Supersedes:** none
- **Superseded by:** none
- **Related:** [V2-1911](https://linear.app/autonominetwork/issue/V2-1911), ADR-0015

## Context

Chunk PUTs currently accept arbitrary content-addressed bytes after payment.
Clients should self-encrypt ordinary files, but raw uploads can contain obvious
image, document, media, archive, database, or executable headers. Nodes need a
cheap admission heuristic that refuses these uploads without parsing files or
attempting to prove that the bytes were produced by self-encryption.

## Decision Drivers

- Keep validation bounded independently of the chunk's length.
- Reduce accidental matches with legitimate encrypted chunks.
- Apply the same admission gate to native and browser client PUTs.
- Preserve existing reads, replication, wire discriminants, and storage formats.

## Considered Options

1. Continue accepting recognizable file bytes.
2. Parse or decompress files, or estimate ciphertext entropy.
3. Classify bounded headers and reject only vetted, corroborated signatures.

## Decision

Use option 3. Run `file-format` with all deep reader features disabled on at
most 265 bytes, which includes the POSIX/GNU tar signature at offset 257.
Keep an explicit admission list; a crate classification alone is not enough
to reject a chunk. Short signatures require supporting fields. HTML and XML
checks inspect at most 64 bytes, and PE EXE/DLL checks read four bytes at the
bounds-checked offset in an MZ header. There is no payload scan, decompression,
entropy calculation, or cryptographic self-encryption verification.

Run this gate after size and content-address validation, before duplicate
acknowledgement, storage access, or payment verification. Existing retrieval
and node-to-node replication paths do not use it.

Return `ChunkPutResponse::Error(ProtocolError::StorageFailed(message))`, using
the existing wire variant and this fixed message:

> chunk has a recognizable file header; self-encrypt files before uploading

Preserve this exact message through the browser error boundary. Treat its
wording as a compatibility contract until a shared typed protocol error replaces
it. The companion client change preflights the same policy before payment and
distinguishes this response from a disk-full rejection. A node-only rollout
can reject bytes after older clients have already paid on-chain; coordinate
the client rollout and document that node admission cannot refund that payment.

## Consequences

### Positive

- Obvious file uploads receive actionable rejections with bounded validation.
- The maintained classifier supplies format signatures without enabling deep readers.
- Stored content remains readable and eligible for replication.

### Negative / Trade-offs

- Headerless plaintext, disguised headers, unsupported formats, and some variants pass.
- Accidental ciphertext matches remain possible; this is not proof of encryption.
- Node and client preflight policies must stay aligned, including classifier versions.
- New direct dependency: `file-format` 0.29, requiring acknowledgement during review.

### Neutral / Operational

- This is a client PUT admission change, not a storage migration or wire-version bump.
- A live dev-testnet rollout and mixed-version check remain release gates.
- Roll back the admission gate if legitimate encrypted uploads are rejected.

## Validation

Tests cover common headers, truncation, near-matches, weak crate classifications,
native/typed PUT parity, unpaid and cached-paid rejection, duplicate rejection,
existing reads, browser error redaction, and a real self-encrypted upload round trip.
Keep strict Clippy, formatting, and no-default-feature compilation passing.
Review signatures and repeat the bounded-runtime check when upgrading the classifier.

## Notes for AI-assisted work

This ADR remains Proposed until human review. Accepted ADRs are immutable.
