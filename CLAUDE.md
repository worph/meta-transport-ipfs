# CLAUDE.md — meta-transport-ipfs

meta-share's IPFS tier, split out 2026-10 (`packages/meta-share/docs/transport-plugins.md`).
Behaviour must stay identical to the monolith's swarm / blockstore / ingress.

## Load-bearing invariants

1. **The swarm is transport-only**: identify/kad/mdns/bitswap. No kamilata, no
   gossipsub, no request_response — search is meta-search's.
2. **`MAX_MULTIHASH_SIZE = 64`** must match meta-gateway and meta-search.
3. **`core2` is patched** in `Cargo.toml` (every libp2p-0.56 bitswap impl needs
   the yanked `^0.4.0`); mirror changes in meta-gateway.
4. **`ipfs_chunk.rs` is kubo-identical** (256 KiB raw leaves, fanout 174), in
   sync with meta-gateway's `hash.rs` and `meta_feeder_sdk::hash`.
5. **Records are never blocks**; `scrub_record_blocks` removes legacy MSR1 rows at
   boot.
6. **Fetch for our user implies seed; the swarm side is provider-only** —
   unattributed blocks over `META_SHARE_LOOSE_BLOCK_MAX_BYTES` are dropped.
7. **`gateway_discovery.rs` is a MIRRORED file** (meta-share hull + meta-search);
   `scripts/check-mirrors.sh` checks it.
8. **Identify announces the hull's URL**, never this container's.
9. **Seed rows, material index and meta-core are the hull's** — report them as
   events (`seed`, `promoted`), don't write them.
10. **Mark, don't meter**: dag-range `/raw` answers carry `x-metamesh-meter:
    egress`; single blocks don't (posters were never throttled).
