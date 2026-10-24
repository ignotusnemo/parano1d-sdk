// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use super::*;
use bincode::Options;
use noid_core::{CanonicalDeserialize, CanonicalSerialize};
use noid_fri_binius::{
    interleaved_commit::{MerkleCap, SourceBatchedMerkleProof},
    zk_capsule_algebra::contract_high3_for_each_low8,
    zk_capsule_pcs::web3::{self as pcs, ClientSource},
    zk_phase_a::prove_phase_a_from_virtual_oracle_adaptive,
};
use zeroize::Zeroizing;

const PREFIX_MAGIC: &[u8; 8] = b"N1DPPD04";
pub const ORACLE_BYTES: usize = 2048 * 32;
pub const MAX_REQUEST_BYTES: usize = ORACLE_BYTES + 8192;

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct Prefix {
    statement: ZkAuthCapsuleOwnerStatement,
    source_cap: [[u8; 32]; 8],
    owner: ZkAuthCapsuleOwnerProof,
    sigma: Block256,
}

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(MAX_REQUEST_BYTES as u64)
        .reject_trailing_bytes()
}

fn fail() -> ZkAuthorizationError {
    ZkAuthorizationError::PhaseABindingMismatch
}

pub struct Prepared {
    address: [Block128; 2],
    commitment: ZkCapsulePcsSourceCommitment,
    source: noid_fri_binius::zk_capsule_pcs::ZkCapsulePcsSourceProverState,
}

pub struct Pending {
    prefix: Prefix,
    source: ClientSource,
}

pub fn prepare(
    state: &ZkAuthCapsuleStateTable,
    address: [Block128; 2],
) -> Result<Prepared, ZkAuthorizationError> {
    let (commitment, source) = zk_capsule_pcs_commit_fresh(state.cells(), &mut rand_core::OsRng)?;
    Ok(Prepared {
        address,
        commitment,
        source,
    })
}

impl Prepared {
    pub fn begin(
        self,
        statement: ZkAuthCapsuleOwnerStatement,
    ) -> Result<(Vec<u8>, Pending), ZkAuthorizationError> {
        if self.address != statement.address {
            return Err(fail());
        }
        let source_cap = self.commitment.transcript_lanes()?;
        let (owner, bound) = zk_capsule_pcs_bind_owner(self.source, |bank| {
            prove_zk_auth_capsule_owner(
                ZkAuthCapsuleBankView::checked(bank)?,
                statement,
                &source_cap,
            )
        })?;
        let (binding, bound) = zk_capsule_pcs_bind_phase_a(
            bound,
            &owner.derived.post_claim_relation.weights,
            owner.derived.bank_claim(),
        )?;
        let sigma = binding.companion_claim;
        let mut channel = init_main_channel(&owner.derived, sigma);
        let gamma = channel.squeeze_wide();
        require_main_gamma(gamma)?;
        let (oracle, source) = pcs::mask_source(bound, gamma)?;
        let prefix = Prefix {
            statement,
            source_cap: self.commitment.cap.hashes.try_into().map_err(|_| fail())?,
            owner: owner.proof,
            sigma,
        };
        let prefix_bytes = options().serialize(&prefix).map_err(|_| fail())?;
        let mut request = Vec::with_capacity(8 + prefix_bytes.len() + ORACLE_BYTES);
        request.extend_from_slice(PREFIX_MAGIC);
        request.extend_from_slice(&prefix_bytes);
        for value in oracle.iter() {
            request.extend_from_slice(&value.to_bytes());
        }
        Ok((request, Pending { prefix, source }))
    }
}

fn read_request(bytes: &[u8]) -> Result<(Prefix, Zeroizing<Vec<Block256>>), ZkAuthorizationError> {
    if bytes.len() > MAX_REQUEST_BYTES
        || bytes.len() < 8 + ORACLE_BYTES
        || &bytes[..8] != PREFIX_MAGIC
    {
        return Err(fail());
    }
    let cut = bytes.len() - ORACLE_BYTES;
    let prefix: Prefix = options().deserialize(&bytes[8..cut]).map_err(|_| fail())?;
    let oracle = Zeroizing::new(
        bytes[cut..]
            .chunks_exact(32)
            .map(<Block256 as CanonicalDeserialize>::deserialize)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| fail())?,
    );
    Ok((prefix, oracle))
}

pub fn request_statement(
    bytes: &[u8],
) -> Result<ZkAuthCapsuleOwnerStatement, ZkAuthorizationError> {
    Ok(read_request(bytes)?.0.statement)
}

fn source_commitment(prefix: &Prefix) -> ZkCapsulePcsSourceCommitment {
    ZkCapsulePcsSourceCommitment {
        cap: MerkleCap {
            hashes: prefix.source_cap.to_vec(),
        },
    }
}

fn derive_queries(
    prefix: &Prefix,
    proof: &ZkAuthorizationProof,
) -> Result<[usize; ZK_CAPSULE_PCS_QUERY_COUNT], ZkAuthorizationError> {
    let source = source_commitment(prefix);
    let owner =
        verify_zk_auth_capsule_owner(prefix.statement, &source.transcript_lanes()?, &prefix.owner)?;
    let mut channel = init_main_channel(&owner, prefix.sigma);
    let gamma = channel.squeeze_wide();
    require_main_gamma(gamma)?;
    let mut challenges = [Block256::ZERO; PHASE_A_VARS];
    for (index, round) in proof.phase_a.rounds.iter().enumerate() {
        absorb_phase_a_round(&mut channel, round);
        challenges[index] = channel.squeeze_wide();
    }
    let phase_a = verify_phase_a(
        &proof.phase_a,
        ZkPhaseARelationClaims {
            bank: owner.bank_claim(),
            companion: prefix.sigma,
        },
        &owner.post_claim_relation.weights,
        gamma,
        &challenges,
        proof.phase_b_value,
    )?;
    absorb_phase_b_prefix(&mut channel, proof.phase_b_value, &proof.upper);
    let beta_source: [Block256; SOURCE_STANDARD_FOLDS] =
        std::array::from_fn(|_| channel.squeeze_wide());
    absorb_mid_commitment(&mut channel, &proof.mid_commitment)?;
    let beta_mid: [Block256; MID_STANDARD_FOLDS] = std::array::from_fn(|_| channel.squeeze_wide());
    absorb_tail(&mut channel, &proof.tail);
    let beta_tail = channel.squeeze_wide();
    let mut beta = [Block256::ZERO; PHASE_B_LOW_VARS];
    beta[..SOURCE_STANDARD_FOLDS].copy_from_slice(&beta_source);
    beta[SOURCE_STANDARD_FOLDS..SOURCE_STANDARD_FOLDS + MID_STANDARD_FOLDS]
        .copy_from_slice(&beta_mid);
    beta[PHASE_B_LOW_VARS - 1] = beta_tail;
    verify_phase_b_upper_tail_link(
        proof.upper.as_array(),
        &phase_a.terminal_point,
        proof.phase_b_value,
        &beta,
        &proof.tail.coefficients,
    )?;
    replay_grind(&mut channel, proof.grind_nonce)?;
    let seeds: [Block128; ZK_AUTH_QUERY_SEEDS] = std::array::from_fn(|_| channel.squeeze_base());
    Ok(zk_authorization_queries_from_seeds(&seeds))
}

/// Server Main/PCS proving from one masked oracle and an existing Owner transcript.
pub fn prove(bytes: &[u8]) -> Result<Vec<u8>, ZkAuthorizationError> {
    let (prefix, oracle) = read_request(bytes)?;
    let source = source_commitment(&prefix);
    let owner =
        verify_zk_auth_capsule_owner(prefix.statement, &source.transcript_lanes()?, &prefix.owner)?;
    let mut channel = init_main_channel(&owner, prefix.sigma);
    let gamma = channel.squeeze_wide();
    require_main_gamma(gamma)?;
    let phase_a = prove_phase_a_from_virtual_oracle_adaptive(
        &oracle,
        &owner.post_claim_relation.weights,
        ZkPhaseARelationClaims {
            bank: owner.bank_claim(),
            companion: prefix.sigma,
        },
        gamma,
        |_index, round| {
            absorb_phase_a_round(&mut channel, &round);
            channel.squeeze_wide()
        },
    )?;
    let low: [Block256; PHASE_B_LOW_VARS] = std::array::from_fn(|i| phase_a.terminal_point[i]);
    let high: [Block256; PHASE_B_HIGH_VARS] =
        std::array::from_fn(|i| phase_a.terminal_point[PHASE_B_LOW_VARS + i]);
    let upper = ZkAuthorizationUpper::new(contract_high3_for_each_low8(
        oracle.as_slice().try_into().map_err(|_| fail())?,
        &high,
    ));
    if evaluate_upper_at_low8(upper.as_array(), &low) != phase_a.terminal_oracle_value {
        return Err(fail());
    }
    absorb_phase_b_prefix(&mut channel, phase_a.terminal_oracle_value, &upper);
    let beta_source = std::array::from_fn(|_| channel.squeeze_wide());
    let (mid_commitment, mut mid) = pcs::commit_mid(&oracle, beta_source)?;
    absorb_mid_commitment(&mut channel, &mid_commitment)?;
    let beta_mid = std::array::from_fn(|_| channel.squeeze_wide());
    let tail = pcs::reveal_tail(&mut mid, beta_mid);
    absorb_tail(&mut channel, &tail);
    let _beta_tail = channel.squeeze_wide();
    let (grind_nonce, _) = grind_main_channel_with_bits(&mut channel, ZK_AUTH_GRIND_BITS)?;
    let seeds: [Block128; ZK_AUTH_QUERY_SEEDS] = std::array::from_fn(|_| channel.squeeze_base());
    let queries = zk_authorization_queries_from_seeds(&seeds);
    let (mid_symbols, mid_batch) = pcs::open_mid(mid, &queries)?;
    // Canonical fixed-size placeholders let the existing allocation-bounded
    // decoder parse this response. The client replaces them before verification.
    let proof = ZkAuthorizationProof {
        source_commitment: source,
        owner: prefix.owner,
        sigma: prefix.sigma,
        phase_a: phase_a.proof,
        phase_b_value: phase_a.terminal_oracle_value,
        upper,
        mid_commitment,
        tail,
        grind_nonce,
        opening: ZkCapsulePcsOpening {
            source_joint_symbols:
                vec![Block128::ZERO; noid_fri_binius::zk_capsule_pcs::ZK_CAPSULE_PCS_SOURCE_SYMBOLS],
            source_batch: SourceBatchedMerkleProof { siblings: vec![] },
            mid_symbols,
            mid_batch,
        },
    };
    proof.to_bytes().map_err(|_| fail())
}

impl Pending {
    /// Consume the attempt before decoding any response. Private openings leave
    /// the client only after the complete original proof verifier accepts.
    pub fn finish(self, response: &[u8]) -> Result<ZkAuthorizationProof, ZkAuthorizationError> {
        let mut proof = ZkAuthorizationProof::from_bytes(response).map_err(|_| fail())?;
        if proof.source_commitment.cap.hashes.as_slice() != self.prefix.source_cap
            || proof.owner != self.prefix.owner
            || proof.sigma != self.prefix.sigma
        {
            return Err(fail());
        }
        let queries = derive_queries(&self.prefix, &proof)?;
        let (symbols, batch) = pcs::open_source(self.source, &queries)?;
        proof.opening.source_joint_symbols = symbols;
        proof.opening.source_batch = batch;
        verify_zk_authorization(self.prefix.statement, &proof)?;
        Ok(proof)
    }
}
