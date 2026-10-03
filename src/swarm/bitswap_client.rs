//! Consumer-side bitswap call path. The HTTP layer's `/ipfs/{cid}`
//! handler calls [`bitswap_get_block`] with a cid and a timeout; the
//! helper sends a [`Command::BitswapGet`] to the swarm task and awaits
//! the reply oneshot.
//!
//! Mirrors `gateway_client.rs` in shape:
//! - [`bitswap_get_block`] — HTTP-side ergonomics helper with timeout.
//! - [`BitswapInflight`] — tracking map from `beetswap::QueryId` to
//!   caller reply channels. Owned by the swarm task; mutated on
//!   `Command::BitswapGet` (insert) and on `beetswap::Event::*` (fire +
//!   remove).
//!
//! The block-fetching path stops at the *block* layer, not the file
//! layer: a single `bitswap.get(cid)` resolves one block. M13's
//! `/ipfs/{cid}` endpoint handles dag-pb traversal — it issues one
//! `bitswap_get_block` per cid (root + children) and reassembles the
//! UnixFS file.

use std::collections::HashMap;
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};
use tracing::warn;

use crate::blockstore::MsCid;

use super::{BitswapGetError, Command};

/// Issue a single-block bitswap fetch and await the bytes (or a
/// transport failure / timeout). The `timeout` is enforced caller-side;
/// beetswap itself has its own per-query budget but a runaway WANT-list
/// shouldn't block the HTTP response.
pub async fn bitswap_get_block(
    swarm_tx: &mpsc::Sender<Command>,
    cid: MsCid,
    timeout: Duration,
) -> Result<Vec<u8>, BitswapGetError> {
    let (reply_tx, reply_rx) = oneshot::channel();
    swarm_tx
        .send(Command::BitswapGet {
            cid,
            reply: reply_tx,
        })
        .await
        .map_err(|_| BitswapGetError::ReplyChannelClosed)?;
    match tokio::time::timeout(timeout, reply_rx).await {
        Ok(Ok(res)) => res,
        // Reply oneshot dropped — swarm task fell over mid-call.
        Ok(Err(_)) => Err(BitswapGetError::ReplyChannelClosed),
        Err(_) => Err(BitswapGetError::QueryFailed(format!(
            "bitswap fetch timed out after {:?}",
            timeout
        ))),
    }
}

/// Inflight map from `beetswap::QueryId` to the caller's reply channel.
/// Owned by the swarm task; mutated on `Command::BitswapGet` (insert)
/// and on `beetswap::Event::{GetQueryResponse, GetQueryError}` (fire +
/// remove).
#[derive(Default)]
pub(super) struct BitswapInflight {
    map: HashMap<beetswap::QueryId, oneshot::Sender<Result<Vec<u8>, BitswapGetError>>>,
}

impl BitswapInflight {
    pub(super) fn new() -> Self {
        Self::default()
    }

    /// Register the reply channel for a newly-issued `bitswap.get`.
    /// The libp2p call must run *before* this — its `QueryId` is what
    /// we key by.
    pub(super) fn register(
        &mut self,
        id: beetswap::QueryId,
        reply: oneshot::Sender<Result<Vec<u8>, BitswapGetError>>,
    ) {
        if self.map.insert(id, reply).is_some() {
            warn!(?id, "bitswap inflight: id collision; overwrote pending reply");
        }
    }

    /// Process a `beetswap::Event` from the swarm. Returns `true` if
    /// the event was a query completion that fired a reply, `false`
    /// otherwise.
    pub(super) fn on_event(&mut self, event: &beetswap::Event) -> bool {
        match event {
            beetswap::Event::GetQueryResponse { query_id, data } => {
                if let Some(tx) = self.map.remove(query_id) {
                    let _ = tx.send(Ok(data.clone()));
                    true
                } else {
                    false
                }
            }
            beetswap::Event::GetQueryError { query_id, error } => {
                if let Some(tx) = self.map.remove(query_id) {
                    let _ = tx.send(Err(BitswapGetError::QueryFailed(error.to_string())));
                    true
                } else {
                    false
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    fn dummy_cid() -> MsCid {
        MsCid::from_str("bafkreifzjut3te2nhyekklss27nh3k72ysco7y32koao5eei66wof36n5e")
            .expect("static cid parses")
    }

    /// Mirrors `call_gateway_returns_swarm_gone_on_dead_channel` — if
    /// the swarm task has exited, the helper surfaces a closed-channel
    /// error rather than hanging.
    #[tokio::test]
    async fn bitswap_get_returns_channel_closed_on_dead_channel() {
        let (tx, rx) = mpsc::channel::<Command>(1);
        drop(rx);
        let res = bitswap_get_block(&tx, dummy_cid(), Duration::from_millis(50)).await;
        assert!(matches!(res, Err(BitswapGetError::ReplyChannelClosed)));
    }

    /// Mirrors `call_gateway_returns_timeout_when_reply_never_arrives` —
    /// if the swarm task accepts the command but never delivers the
    /// reply, the caller-side timeout fires.
    #[tokio::test]
    async fn bitswap_get_returns_timeout_when_reply_never_arrives() {
        let (tx, mut rx) = mpsc::channel::<Command>(1);
        let pump = tokio::spawn(async move {
            let _held = rx.recv().await;
            tokio::time::sleep(Duration::from_secs(60)).await;
            drop(_held);
        });
        let res = bitswap_get_block(&tx, dummy_cid(), Duration::from_millis(50)).await;
        pump.abort();
        match res {
            Err(BitswapGetError::QueryFailed(msg)) => {
                assert!(msg.contains("timed out"), "got `{msg}`");
            }
            other => panic!("expected timed-out QueryFailed, got {other:?}"),
        }
    }
}
