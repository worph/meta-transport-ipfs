//! The record block shape (`MSR1` + bincode), kept only so the ipfs tier can
//! recognise — and scrub — record blocks that older builds wrote into the block
//! table (`filestore::scrub_record_blocks`). Copied from meta-share's
//! `store.rs`; the record *cache* stays in the hull.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};


/// One metadata record. `cid` is the externally-canonical CID — preferred
/// for content addressing across the swarm, derived by rank (IPFS >
/// sha-family > btih > midhash) from the source peer's bare-CID key-set —
/// `canonical_cid` is no longer a stored field (see ingest::cid_rank).
/// `cids` carries every CID variant the source peer knows about for this
/// file, so a lookup by any of them (sha256 when canonical is ipfs, etc.)
/// can still match locally.
///
/// `tokens` is retained on the wire/struct shape for backward compatibility
/// with peers and blocks produced by older builds (it serialises empty now
/// that there is no tokenizer); decoders tolerate either.
///
/// `fields` carries human-readable key/value metadata (fileName, sizeByte,
/// mimeType, etc.) that the UI renders as a table.
///
/// `#[serde(default)]` on `cids` and `fields` keeps the wire format
/// backward-compatible with peers running older builds — they emit empty
/// values and we tolerate them on receive.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub cid: String,
    pub title: String,
    pub year: Option<u32>,
    pub tokens: Vec<String>,
    #[serde(default)]
    pub cids: Vec<String>,
    #[serde(default)]
    pub fields: BTreeMap<String, String>,
}

/// Encoding format errors for record blocks stored in `RedbBlockstore`.
/// Kept narrow so callers can distinguish "wrong format on disk" from
/// "transport / IO failure" without string-matching.
#[derive(Debug, thiserror::Error)]
pub enum RecordBlockError {
    #[error("block too short to be an MSR1 record (got {0} bytes)")]
    TooShort(usize),
    #[error("block magic mismatch: expected MSR1, got {0:?}")]
    BadMagic([u8; 4]),
    #[error("bincode encode failed: {0}")]
    Encode(#[from] bincode::error::EncodeError),
    #[error("bincode decode failed: {0}")]
    Decode(#[from] bincode::error::DecodeError),
}

impl Record {
    /// Serialise to the on-disk block form used by `RedbBlockstore`:
    /// `MSR1` magic prefix + bincode-encoded payload. The magic gives
    /// us a single-byte cheap reject on format drift; future record-
    /// shape changes bump to `MSR2` and decoders refuse the old shape
    /// loudly rather than silently producing garbage.
    ///
    /// Test-only: nothing writes record blocks any more. Tests build them to
    /// exercise the boot scrub and the relay sniff that still recognise them.
    #[cfg(test)]
    pub fn encode_block(&self) -> Result<Vec<u8>, RecordBlockError> {
        let payload = bincode::serde::encode_to_vec(self, bincode::config::standard())?;
        let mut out = Vec::with_capacity(crate::blockstore::RECORD_BLOCK_MAGIC.len() + payload.len());
        out.extend_from_slice(crate::blockstore::RECORD_BLOCK_MAGIC);
        out.extend_from_slice(&payload);
        Ok(out)
    }

    /// Decode an MSR1-prefixed block back into a `Record`. Rejects
    /// anything that doesn't start with the magic — including blocks
    /// produced by the IPFS gateway tier (raw bytes / dag-pb), which
    /// share the same blockstore but never carry our prefix.
    pub fn decode_block(bytes: &[u8]) -> Result<Self, RecordBlockError> {
        let magic = crate::blockstore::RECORD_BLOCK_MAGIC;
        if bytes.len() < magic.len() {
            return Err(RecordBlockError::TooShort(bytes.len()));
        }
        let (prefix, payload) = bytes.split_at(magic.len());
        if prefix != magic {
            let mut got = [0u8; 4];
            got.copy_from_slice(prefix);
            return Err(RecordBlockError::BadMagic(got));
        }
        let (record, _) = bincode::serde::decode_from_slice(payload, bincode::config::standard())?;
        Ok(record)
    }
}
