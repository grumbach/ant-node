# v12 — open design gaps (next steps, not blocking the relay-focused run)

## Quote-quantity audit (deferred Phase-3 continuation)

**Gap:** A node's storage quote price is now computed from its true local
held-count (deletion-aware resync from `current_chunks()`), but that count is
**self-reported and unverifiable by peers**. Confirmed across the stack:

- `PaymentQuote` (evmlib `data_payments.rs`) signs only
  `content/timestamp/price/rewards_address/pub_key/signature` — the
  price-driving `records_stored` count is NOT in the signed payload.
- Client (`ant-client .../client/quote.rs::classify_quote_response`) checks
  only `BLAKE3(pub_key)==peer_id`; it deliberately skips even quote-signature
  verification and never sanity-checks the price magnitude.
- The v12 audit proves possession of *sampled committed keys* but is fully
  decoupled from quoting; the commitment's `key_count` and the quote's
  price-driving count are separate, unlinked numbers.

Net: honest nodes price correctly (deletion lowers their earnings), but a
malicious node can sign any price — nobody verifies the quantity.

**Proposed fix (reuses existing machinery):** bind the quote to the audited
commitment. Put `key_count` (or the latest `StorageCommitment` hash) into the
**signed `PaymentQuote` payload**, so a verifier can cheaply check
`price == calculate_price(key_count)` while the existing v12 audit proves those
`key_count` keys are genuinely held (sample → Merkle proofs). Inflating price
then requires inflating `key_count`, which the audit catches.

**Cost:** wire-format change to `PaymentQuote` in evmlib/ant-protocol → a
coordinated version bump, not a node-local change. Track for the PR #113
reviewers as the Phase-3 quoting/holder-credit integration.
