# meta-transport-ipfs

meta-share's **IPFS tier** as a transport plugin (`meta_feeder_sdk::transport`).

- The libp2p host: identify + kad (client) + mdns + bitswap (`beetswap`,
  `MAX_MULTIHASH_SIZE = 64`), on `P2P_LISTEN` (4001 — publish it; `PUBLIC_ADDR`
  announces it). Identify carries the **hull's** `baseUrl`, so peers keep calling
  meta-share's public API.
- The blockstore (`<data>/ipfs/blocks.redb`): material blocks + **leaf refs into
  files** (meta-core library files over WebDAV / a local `/files` mount, and cache
  containers on the shared volume) — one copy on disk.
- Bitswap ingress: big dag-pb fetches land in `tmp/<cid>/` and are renamed into
  `cache/`; a genuine play commits them to a background fill.
- Gateway discovery (identify `gateways=` → `GET {baseUrl}/api/gateway/plugins`),
  exposed to the hull as `/ipfs-tier/directory`.
- Serves the public `/ipfs/:cid` gateway (relayed by the hull) and the hull's
  `/ipfs-tier/*` facade.

## Configuration

meta-share's variables, unchanged: `P2P_LISTEN`, `PUBLIC_ADDR`, `KAD_*`,
`BOOTSTRAP_PEERS`, `ENABLE_MDNS`, `TARGET_PEER_COUNT`, `META_SHARE_MAX_CONNS`,
`META_SHARE_BLOCKSTORE_CACHE_MB`, `META_SHARE_INGRESS_*`,
`META_SHARE_LOOSE_BLOCK_MAX_BYTES`, `META_SHARE_LOCAL_FILES_PATH`,
`META_SHARE_FILES_PATH`, `META_SHARE_SEED_DHT_PROVIDE`, `META_SHARE_DATA`, plus
`META_SHARE_HULL_URL`. `meta_core_url` / `peer_url` are asked from the hull at
boot (`GET /internal/network`), env as the fallback.

**Own settings** (config plane, `META_SHARE_PLUGIN_STATE_DIR`, default `/state` →
`config.json`): cohort namespace, DHT/pinned bootstrap peers, mDNS, DHT announce,
max connections, background completion. Edited from meta-share's dashboard
(Plugins → ipfs → configure); `config.json` wins and is written onto the env names
above at boot, so env only seeds it. Saving restarts the plugin. `PUBLIC_ADDR` /
`P2P_LISTEN` stay env-only (they follow the published port and the box's IP).

Boot order is handled here, not by compose: before opening `ipfs/blocks.redb` the
plugin waits (≤ 60 s) for the hull's `/health`, because the hull migrates its
material index out of that file on its first boot after the split and redb is
single-process.

## Build

```bash
docker build -t meta-transport-ipfs .
docker build --build-context sdk=../meta-feeder-sdk -t meta-transport-ipfs .
```
