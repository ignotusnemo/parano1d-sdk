// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Block-header hash.
//!
//! `H_BLOCK` absorbs all consensus-significant header fields in the order
//! declared below, using capacity IV = `BLOCKHDR`. Each 32-byte digest is
//! absorbed as two `Block128` halves (hi then lo, little-endian). Scalar
//! integers are absorbed as a single `Block128` word (zero-extended).
//!
//! **Field order is locked. Future fields MUST be appended at the end**,
//! never reordered. Consensus nodes reject any header whose byte count
//! does not equal `BLOCK_HEADER_WIRE_SIZE`.

use noid_core::Block128;
use noid_poseidon2b::native::compression::Poseidon2bSponge;
use noid_poseidon2b::native::domain::{capacity_iv, TAG_BLOCKHDR, TAG_SEMHDR};
use noid_poseidon2b::primitives::{Address, Digest};

/// Canonical block header.
///
/// Byte layout (see `BLOCK_HEADER_WIRE_SIZE` in `wire.rs`):
///
/// ```text
///   prev_block_hash       [32B]  hash of previous header
///   state_root            [32B]  exact sparse-Merkle UTXO root
///   tx_root               [32B]  count-bound universal transaction root
///   timestamp             [8B]   seconds since Unix epoch (LE u64)
///   height                [8B]   block height (LE u64)
///   miner_address         [32B]  coinbase recipient address
///   nonce                 [16B]  128-bit Poseidon2b PoW nonce (LE u128)
///   difficulty_target     [32B]  256-bit ASERT target
///   log_slots             [4B]   current slot-space depth (LE u32)
///   active_slot_count     [8B]   live UTXO count after this block (LE u64)
///   alloc_counter         [8B]   monotonic PRNG seed after this block (LE u64)
/// ```
///
/// Total: 212 bytes (see `BLOCK_HEADER_WIRE_SIZE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct BlockHeader {
    pub prev_block_hash: Digest,
    /// Exact sparse-Merkle root over the UTXO slot vector.
    pub state_root: Digest,
    /// Count-bound `TAG_TXROOT` wrap of the universal 256-leaf transaction tree.
    pub tx_root: Digest,
    pub timestamp: u64,
    pub height: u64,
    pub miner_address: Address,
    /// 128-bit Poseidon2b PoW nonce.
    pub nonce: u128,
    /// 256-bit ASERT difficulty target (LE). Block valid iff
    /// `H_POSEIDON_POW(header) < difficulty_target`.
    pub difficulty_target: [u8; 32],
    /// Slot-space depth: `log₂(num_slots)`. Production values are in
    /// `[LOG_SLOTS_GENESIS, LOG_SLOTS_MAX]`; small in-memory fixtures may use
    /// reduced domains. Replicated in every Fiat-Shamir
    pub log_slots: u32,
    /// Number of live (non-empty) slots after all transactions in this block
    /// are applied. Each hard-finalized value is an input to the state-depth
    /// expansion rule. MUST equal `ChainState::active_slot_count` after
    /// `apply_block`.
    pub active_slot_count: u64,
    /// Monotonic PRNG seed: incremented on every successful mint.
    /// MUST equal `ChainState::alloc_counter` after `apply_block`.
    pub alloc_counter: u64,
}

/// Compute the semantic `block_id` — the Poseidon2b hash of the canonical
/// semantic header.
///
/// Header identity is also used by the separate 144-block transaction epoch.
/// and for chain linking (`prev_block_hash`).
pub fn hash_block_header(hdr: &BlockHeader) -> Digest {
    let mut s = Poseidon2bSponge::with_iv(capacity_iv(TAG_BLOCKHDR));

    absorb_digest(&mut s, &hdr.prev_block_hash);
    absorb_digest(&mut s, &hdr.state_root);
    absorb_digest(&mut s, &hdr.tx_root);
    s.absorb(Block128::from(hdr.timestamp as u128));
    s.absorb(Block128::from(hdr.height as u128));
    absorb_digest(&mut s, hdr.miner_address.as_bytes());
    s.absorb(Block128::from(hdr.nonce));
    absorb_digest(&mut s, &hdr.difficulty_target);
    s.absorb(Block128::from(hdr.log_slots as u128));
    s.absorb(Block128::from(hdr.active_slot_count as u128));
    s.absorb(Block128::from(hdr.alloc_counter as u128));

    s.finalize()
}

/// Explicit alias for the consensus semantic chain-link id.
#[inline]
pub fn block_id(hdr: &BlockHeader) -> Digest {
    hash_block_header(hdr)
}

/// Compute the nonce-free semantic header projection `C` under `SEMHDR__`.
///
/// Absorbs every consensus-significant field in exactly the
/// `hash_block_header` order with the nonce skipped, so one template has one
/// projection across every nonce. A HistoryStep terminal binds this value;
/// the chain-link identity stays `block_id` (`BLOCKHDR`, nonce included) and
/// every accepting node natively requires the two to agree on one header.
pub fn semantic_header_id(hdr: &BlockHeader) -> Digest {
    let mut s = Poseidon2bSponge::with_iv(capacity_iv(TAG_SEMHDR));

    absorb_digest(&mut s, &hdr.prev_block_hash);
    absorb_digest(&mut s, &hdr.state_root);
    absorb_digest(&mut s, &hdr.tx_root);
    s.absorb(Block128::from(hdr.timestamp as u128));
    s.absorb(Block128::from(hdr.height as u128));
    absorb_digest(&mut s, hdr.miner_address.as_bytes());
    absorb_digest(&mut s, &hdr.difficulty_target);
    s.absorb(Block128::from(hdr.log_slots as u128));
    s.absorb(Block128::from(hdr.active_slot_count as u128));
    s.absorb(Block128::from(hdr.alloc_counter as u128));

    s.finalize()
}

#[inline]
fn absorb_digest(s: &mut Poseidon2bSponge, d: &Digest) {
    let hi = Block128::from(u128::from_le_bytes(d[..16].try_into().unwrap()));
    let lo = Block128::from(u128::from_le_bytes(d[16..].try_into().unwrap()));
    s.absorb_pair(hi, lo);
}

impl BlockHeader {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != 212 {
            return Err("Invalid canonical parent header length".into());
        }
        Ok(Self {
            prev_block_hash: bytes[0..32].try_into().unwrap(),
            state_root: bytes[32..64].try_into().unwrap(),
            tx_root: bytes[64..96].try_into().unwrap(),
            timestamp: u64::from_le_bytes(bytes[96..104].try_into().unwrap()),
            height: u64::from_le_bytes(bytes[104..112].try_into().unwrap()),
            miner_address: Address(bytes[112..144].try_into().unwrap()),
            nonce: u128::from_le_bytes(bytes[144..160].try_into().unwrap()),
            difficulty_target: bytes[160..192].try_into().unwrap(),
            log_slots: u32::from_le_bytes(bytes[192..196].try_into().unwrap()),
            active_slot_count: u64::from_le_bytes(bytes[196..204].try_into().unwrap()),
            alloc_counter: u64::from_le_bytes(bytes[204..212].try_into().unwrap()),
        })
    }
}
