# HIM Proof Seal verifier

Open-source verifier for [HIM (Human Intelligence Mining)](https://him.finance) rounds. It checks a round against Solana mainnet without trusting any HIM server for the math.

Before a round, every question and its answer key is hashed into a Merkle tree and the root is written to Solana in an SPL Memo. After the round, the settled result is sealed the same way. This script:

1. fetches the round's openings and Merkle paths from the public HIM API,
2. recomputes every leaf and path with SHA-256,
3. reads the memo from Solana and checks the text, the signer (the seal key) and the timestamp,
4. checks that every question was sealed **before** the round's first question.

No dependencies: Node 18+ built-ins only.

## Run

```bash
node verify-proof.mjs <roundId>
node verify-proof.mjs --epoch <n>
node verify-proof.mjs <roundId> --json
```

Options: `--human-trace <file.json>` (a Human check trace you saved from the site: its hash must equal the sealed `th` of one human-check leaf), `--api <url>` (default `https://api.him.finance/escrow`), `--rpc <url>` (default the public Solana mainnet RPC, or `$SOLANA_RPC_URL`).

Example, a real mainnet round (settled 10 Oct 2026):

```bash
node verify-proof.mjs 56f94a5663ac237e8074f260d2b0afdd9b050f8935adef48975566a24d7df6f1
# ... PASS lines ...
# RESULT: PASS - verified against the chain
```

Seal signer on Solana mainnet: `2NrV3dn1DPL9dWvQfnndejyyjR4p2b2puAwp8nC7uGpJ`. Open it on any Solana explorer to see every seal.

## Encoding (public contract)

- Question leaf: `sha256(0x00 || "HIM1|ql|" || opening)`; result leaf: `sha256(0x00 || "HIM1|rl|" || record)`; node: `sha256(0x01 || left || right)`.
- An opening carries the question, its options, the answer index and a random salt, so a root can never be used as an answer lookup.
- Human check leaf (when a player took the optional Human check after a round): `sha256(0x00 || "HIM1|hl|" || record)`, in the same result tree, so the normal results memo seals it. The record holds a pseudonymous player id, the seed, the sha256 of the trace (`th`), the score and the verdict. It is a signal, not proof, and it never changes a result.
- Memo text: `HIM1|q|<epoch>|<root>` (questions, before play) and `HIM1|r|<epoch>|<root>` (results, after).
- The golden vectors in `verify-proof.test.mjs` are the same constants the HIM engine pins; they must agree byte for byte.

## Test

```bash
node --test verify-proof.test.mjs
```

## License

MIT
