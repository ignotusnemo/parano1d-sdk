// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Canonical block transaction tree.
//!
//! Every non-genesis block occupies the same 256-leaf namespace: coinbase at
//! position zero, user transactions in canonical block order at positions
//! `1..=255`, followed by an all-zero suffix.  The Merkle root is wrapped with
//! the real transaction count so appending or dropping a zero-valued leaf
//! cannot preserve the header commitment.  Genesis is the sole empty case and
//! keeps the protocol zero root.

use noid_poseidon2b::native::domain::TAG_TXROOT;
use noid_poseidon2b::native::{compress, compress_with_tag};
use noid_poseidon2b::primitives::Digest;

/// Number of leaves in the universal transaction namespace.
pub const TX_TREE_LEAVES: usize = 256;
/// Fixed receipt/path depth for every non-genesis transaction.
pub const TX_TREE_DEPTH: usize = 8;

#[inline]
fn count_digest(tx_count: usize) -> Digest {
    debug_assert!((1..=TX_TREE_LEAVES).contains(&tx_count));
    let mut digest = [0u8; 32];
    digest[..16].copy_from_slice(&(tx_count as u128).to_le_bytes());
    digest
}

/// Bind the real non-zero transaction count to a 256-leaf Merkle root.
#[inline]
pub fn bind_tx_count(merkle_root: Digest, tx_count: usize) -> Digest {
    assert!(
        (1..=TX_TREE_LEAVES).contains(&tx_count),
        "non-genesis tx count must fit the universal tree"
    );
    compress_with_tag(TAG_TXROOT, &merkle_root, &count_digest(tx_count))
}

/// Compute the canonical header root from transaction body hashes.
///
/// An empty slice represents genesis and returns `ZERO_DIGEST`.  Every other
/// slice is placed at the start of the universal namespace and zero-padded to
/// 256 leaves before the real count is hash-bound.
pub fn root_from_hashes(tx_hashes: &[Digest]) -> Digest {
    if tx_hashes.is_empty() {
        return [0u8; 32];
    }
    assert!(
        tx_hashes.len() <= TX_TREE_LEAVES,
        "transaction list exceeds universal tree"
    );

    let mut layer = vec![[0u8; 32]; TX_TREE_LEAVES];
    layer[..tx_hashes.len()].copy_from_slice(tx_hashes);
    while layer.len() > 1 {
        layer = layer
            .chunks_exact(2)
            .map(|pair| compress(&pair[0], &pair[1]))
            .collect();
    }
    bind_tx_count(layer[0], tx_hashes.len())
}

/// Build the fixed-depth inclusion path for one real transaction leaf.
pub fn path_from_hashes(tx_hashes: &[Digest], tx_index: usize) -> [Digest; TX_TREE_DEPTH] {
    assert!(!tx_hashes.is_empty(), "genesis has no transaction paths");
    assert!(tx_hashes.len() <= TX_TREE_LEAVES);
    assert!(
        tx_index < tx_hashes.len(),
        "path index must name a real leaf"
    );

    let mut layer = vec![[0u8; 32]; TX_TREE_LEAVES];
    layer[..tx_hashes.len()].copy_from_slice(tx_hashes);
    let mut path = Vec::with_capacity(TX_TREE_DEPTH);
    let mut index = tx_index;

    while layer.len() > 1 {
        path.push(layer[index ^ 1]);
        layer = layer
            .chunks_exact(2)
            .map(|pair| compress(&pair[0], &pair[1]))
            .collect();
        index >>= 1;
    }
    debug_assert_eq!(path.len(), TX_TREE_DEPTH);
    path.try_into().expect("universal tree has fixed depth")
}

/// Verify a fixed-depth path and apply the same count wrapper as the header.
pub fn verify_path(
    leaf: Digest,
    path: &[Digest; TX_TREE_DEPTH],
    tx_index: usize,
    tx_count: usize,
    claimed_root: Digest,
) -> bool {
    if !(1..=TX_TREE_LEAVES).contains(&tx_count) || tx_index >= tx_count {
        return false;
    }

    let mut current = leaf;
    for (level, sibling) in path.iter().enumerate() {
        current = if (tx_index >> level) & 1 == 1 {
            compress(sibling, &current)
        } else {
            compress(&current, sibling)
        };
    }
    bind_tx_count(current, tx_count) == claimed_root
}
