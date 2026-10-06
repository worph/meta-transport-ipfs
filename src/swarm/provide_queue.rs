//! Bounded admission for per-CID DHT announcements.
//!
//! Every `Command::Provide` is a `kad.start_providing`, and every one of those is
//! a full DHT walk: find the ~20 closest peers to the key, then dial each to store
//! the record. Firing them unbounded turns a batch of seeds into a dial storm. On
//! watch.nsl.sh (2026-10-06 18:14:46) a lapsed playback-focus lease released 45
//! queued poster seeds in one second; 45 concurrent walks took this plugin from
//! ~300 to 8,066 log lines a minute (6.8k failed dials) while a viewer was
//! mid-episode.
//!
//! So announcements queue here and at most `max_in_flight` walks run at once.
//! The queue is pure bookkeeping (no swarm, no I/O) so its rules are unit-tested;
//! [`super::event_loop`] feeds it commands and query results and starts whatever
//! [`ProvideQueue::next_to_start`] hands back.
//!
//! What it does NOT bound: libp2p-kad's own periodic republication of records
//! already provided (`provider_publication_interval`), which kad paces itself.

use std::collections::{HashSet, VecDeque};

use libp2p::kad::{QueryId, RecordKey};

/// Default number of concurrent announce walks (`META_SHARE_PROVIDE_CONCURRENCY`).
pub(crate) const DEFAULT_PROVIDE_CONCURRENCY: usize = 2;

pub(crate) struct ProvideQueue {
    pending: VecDeque<RecordKey>,
    queued: HashSet<RecordKey>,
    in_flight: HashSet<QueryId>,
    max_in_flight: usize,
}

impl ProvideQueue {
    /// `max_in_flight == 0` is treated as 1: a queue that never drains would
    /// silently stop announcing anything.
    pub(crate) fn new(max_in_flight: usize) -> Self {
        Self {
            pending: VecDeque::new(),
            queued: HashSet::new(),
            in_flight: HashSet::new(),
            max_in_flight: max_in_flight.max(1),
        }
    }

    /// Queue `key`. `false` if it is already waiting (a re-seed of the same cid
    /// before its turn costs nothing extra).
    pub(crate) fn enqueue(&mut self, key: RecordKey) -> bool {
        if !self.queued.insert(key.clone()) {
            return false;
        }
        self.pending.push_back(key);
        true
    }

    /// Drop a still-waiting `key` (its seed was removed before its turn). A walk
    /// already in flight is left alone; the caller's `stop_providing` covers it.
    pub(crate) fn cancel(&mut self, key: &RecordKey) {
        if self.queued.remove(key) {
            self.pending.retain(|k| k != key);
        }
    }

    /// The next key to announce, if a slot is free. The caller must report the
    /// started query with [`started`](Self::started), or [`failed_to_start`](Self::failed_to_start).
    pub(crate) fn next_to_start(&mut self) -> Option<RecordKey> {
        if self.in_flight.len() >= self.max_in_flight {
            return None;
        }
        let key = self.pending.pop_front()?;
        self.queued.remove(&key);
        Some(key)
    }

    pub(crate) fn started(&mut self, qid: QueryId) {
        self.in_flight.insert(qid);
    }

    /// `start_providing` refused synchronously (e.g. the record store is full):
    /// nothing is in flight, so there is nothing to record. Exists so the call
    /// site reads symmetrically.
    pub(crate) fn failed_to_start(&mut self) {}

    /// A `StartProviding` query finished. `true` if it was one of ours (the
    /// namespace re-publish uses the same query type and is not queued).
    pub(crate) fn finished(&mut self, qid: QueryId) -> bool {
        self.in_flight.remove(&qid)
    }

    pub(crate) fn pending_len(&self) -> usize {
        self.pending.len()
    }

    pub(crate) fn in_flight_len(&self) -> usize {
        self.in_flight.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::kad::{store::MemoryStore, Behaviour};
    use libp2p::{identity, PeerId};

    fn key(n: u8) -> RecordKey {
        RecordKey::new(&[n])
    }

    /// Real `QueryId`s can only be minted by a kad behaviour; start throwaway
    /// queries on one (nothing is ever polled, so no I/O happens).
    fn qids(n: usize) -> Vec<QueryId> {
        let peer = PeerId::from(identity::Keypair::generate_ed25519().public());
        let mut kad = Behaviour::new(peer, MemoryStore::new(peer));
        (0..n).map(|i| kad.get_providers(key(i as u8))).collect()
    }

    #[test]
    fn at_most_max_in_flight_walks_run_at_once() {
        let mut q = ProvideQueue::new(2);
        for n in 0..45 {
            assert!(q.enqueue(key(n)));
        }
        let ids = qids(3);
        assert_eq!(q.next_to_start(), Some(key(0)));
        q.started(ids[0]);
        assert_eq!(q.next_to_start(), Some(key(1)));
        q.started(ids[1]);
        assert_eq!(q.next_to_start(), None, "both slots busy");
        assert_eq!(q.pending_len(), 43);

        assert!(q.finished(ids[0]));
        assert_eq!(q.next_to_start(), Some(key(2)), "a finished walk frees its slot, FIFO");
        q.started(ids[2]);
        assert_eq!(q.in_flight_len(), 2);
    }

    #[test]
    fn a_duplicate_waits_once_and_a_cancelled_key_never_starts() {
        let mut q = ProvideQueue::new(1);
        assert!(q.enqueue(key(1)));
        assert!(!q.enqueue(key(1)), "already queued");
        assert!(q.enqueue(key(2)));
        q.cancel(&key(1));
        assert_eq!(q.next_to_start(), Some(key(2)));
        assert_eq!(q.pending_len(), 0);
        // Once started (dequeued), the same cid may be queued again.
        assert!(q.enqueue(key(2)));
    }

    #[test]
    fn a_foreign_query_does_not_free_a_slot() {
        let mut q = ProvideQueue::new(1);
        q.enqueue(key(1));
        q.enqueue(key(2));
        let ids = qids(2);
        q.next_to_start();
        q.started(ids[0]);
        assert!(!q.finished(ids[1]), "the namespace re-publish is not ours");
        assert_eq!(q.next_to_start(), None);
    }

    #[test]
    fn zero_concurrency_still_drains() {
        let mut q = ProvideQueue::new(0);
        q.enqueue(key(1));
        assert_eq!(q.next_to_start(), Some(key(1)));
    }
}
