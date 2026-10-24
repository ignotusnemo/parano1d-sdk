// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;

/// Client-owned source opening material. Every attempt is consumed once.
pub struct ClientSource {
    bank_codeword: Zeroizing<Vec<Block128>>,
    companion_codeword: Zeroizing<Vec<Block256>>,
    source_tree: SourceHashMerkleTree,
}

/// Release the companion-masked oracle after Owner and sigma are bound.
pub fn mask_source(
    bound: ZkCapsulePcsPhaseABoundProverState,
    gamma: Block256,
) -> Result<(Zeroizing<Vec<Block256>>, ClientSource), ZkCapsulePcsError> {
    require_gamma(gamma)?;
    let oracle = Zeroizing::new(phase_a_virtual_oracle(
        &bound.bank,
        &bound.companion,
        gamma,
    )?);
    Ok((
        oracle,
        ClientSource {
            bank_codeword: bound.bank_codeword,
            companion_codeword: bound.companion_codeword,
            source_tree: bound.source_tree,
        },
    ))
}

/// Open one locally derived query set. No server-supplied query indices enter here.
pub fn open_source(
    source: ClientSource,
    queries: &[usize],
) -> Result<(Vec<Block128>, SourceBatchedMerkleProof), ZkCapsulePcsError> {
    preflight_queries(queries)?;
    let code = ZkAffineLchCode::selected()?;
    let mut symbols = Vec::with_capacity(ZK_CAPSULE_PCS_SOURCE_SYMBOLS);
    let mut leaves = Vec::with_capacity(queries.len());
    for &query in queries {
        let mapping = map_source_query_leaf(query)?;
        leaves.push(mapping.source_leaf_index);
        symbols.extend_from_slice(&build_fold_normal_joint_source_leaf(
            &code,
            &source.bank_codeword,
            &source.companion_codeword,
            mapping.source_leaf_index,
        )?);
    }
    let batch = build_source_batched_merkle_proof_to_cap(
        &source.source_tree,
        &leaves,
        ZK_CAPSULE_PCS_SOURCE_TREE_DEPTH,
        ZK_CAPSULE_PCS_SOURCE_CAP_DEPTH,
        CommitmentHashBackend::Arithmetic,
        &CapsuleNodeHasher,
    );
    Ok((symbols, batch))
}

pub struct ServerMid {
    message: Zeroizing<Vec<Block256>>,
    codeword: Zeroizing<Vec<Block256>>,
    tree: SourceHashMerkleTree,
}

pub fn commit_mid(
    oracle: &[Block256],
    beta: [Block256; SOURCE_STANDARD_FOLDS],
) -> Result<(ZkCapsulePcsMidCommitment, ServerMid), ZkCapsulePcsError> {
    let code = ZkAffineLchCode::selected()?;
    let mut message = Zeroizing::new(oracle.to_vec());
    for challenge in beta {
        fold_lowest_zeroizing(&mut message, challenge);
    }
    let codeword =
        Zeroizing::new(code.encode_extension_after_low_folds(&message, SOURCE_STANDARD_FOLDS)?);
    let tree = build_mid_tree(&codeword);
    let cap = ZkCapsulePcsMidCommitment {
        cap: MerkleCap {
            hashes: tree.get_layer_at_depth(ZK_CAPSULE_PCS_MID_CAP_DEPTH),
        },
    };
    Ok((
        cap,
        ServerMid {
            message,
            codeword,
            tree,
        },
    ))
}

pub fn reveal_tail(
    mid: &mut ServerMid,
    beta: [Block256; MID_STANDARD_FOLDS],
) -> ZkCapsulePcsTailReveal {
    for challenge in beta {
        fold_lowest_zeroizing(&mut mid.message, challenge);
    }
    ZkCapsulePcsTailReveal {
        coefficients: mid.message.as_slice().try_into().expect("tail16"),
    }
}

pub fn open_mid(
    mid: ServerMid,
    queries: &[usize],
) -> Result<(Vec<Block256>, SourceBatchedMerkleProof), ZkCapsulePcsError> {
    preflight_queries(queries)?;
    let code = ZkAffineLchCode::selected()?;
    let mut symbols = Vec::with_capacity(ZK_CAPSULE_PCS_MID_SYMBOLS);
    let mut leaves = Vec::with_capacity(queries.len());
    for &query in queries {
        let mapping = map_source_query_leaf(query)?;
        leaves.push(mapping.mid_leaf_index);
        symbols.extend_from_slice(&build_fold_normal_mid_leaf(
            &code,
            &mid.codeword,
            mapping.mid_leaf_index,
        )?);
    }
    let batch = build_source_batched_merkle_proof_to_cap(
        &mid.tree,
        &leaves,
        ZK_CAPSULE_PCS_MID_TREE_DEPTH,
        ZK_CAPSULE_PCS_MID_CAP_DEPTH,
        CommitmentHashBackend::Arithmetic,
        &CapsuleNodeHasher,
    );
    Ok((symbols, batch))
}
