// SPDX-License-Identifier: Apache-2.0

use super::*;
use noid_tx::PagedSpendIntent;

#[derive(Serialize)]
struct Summary {
    logical_txid: [u8; 32],
    inputs: Vec<(u32, Address)>,
    outputs: Vec<(u32, u64, Address)>,
    fee_micronoid: u64,
    confirmed_height: u64,
    confirmed_unix: u64,
}

#[derive(Serialize)]
struct Receipt {
    construction_marker: u8,
    paged_spend: Vec<u8>,
    tx_index: u16,
    tx_count: u16,
    merkle_path: [[u8; 32]; 8],
    claimed_root: [u8; 32],
    claimed_height: u64,
    summary: Summary,
}

pub fn header_from_rpc(v: &Value) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(212);
    for field in ["prev_hash", "state_root", "tx_root"] {
        out.extend_from_slice(&hash(v[field].as_str().ok_or("Missing header digest")?)?);
    }
    for field in ["timestamp", "height"] {
        out.extend_from_slice(
            &v[field]
                .as_u64()
                .ok_or("Missing header integer")?
                .to_le_bytes(),
        );
    }
    out.extend_from_slice(
        &Address::parse(v["miner"].as_str().ok_or("Missing miner")?)
            .map_err(|e| e.to_string())?
            .0,
    );
    let nonce = hex::decode(v["nonce_hex"].as_str().ok_or("Missing nonce")?)
        .map_err(|_| "Invalid nonce")?;
    require(nonce.len() == 16)?;
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&hash(
        v["difficulty_target"].as_str().ok_or("Missing target")?,
    )?);
    out.extend_from_slice(
        &u32::try_from(v["log_slots"].as_u64().ok_or("Missing State level")?)
            .map_err(|_| "Invalid State level")?
            .to_le_bytes(),
    );
    for field in ["active_slot_count", "alloc_counter"] {
        out.extend_from_slice(
            &v[field]
                .as_u64()
                .ok_or("Missing State count")?
                .to_le_bytes(),
        );
    }
    let header = header::BlockHeader::from_bytes(&out)?;
    require(header::block_id(&header) == hash(v["hash"].as_str().ok_or("Missing header hash")?)?)?;
    Ok(out)
}

pub fn build(
    header_bytes: &[u8],
    parent_bytes: &[u8],
    intent_bytes: &[u8],
    index: usize,
    hashes: &[[u8; 32]],
) -> Result<Vec<u8>> {
    let header = header::BlockHeader::from_bytes(header_bytes)?;
    let parent = header::BlockHeader::from_bytes(parent_bytes)?;
    require(
        !hashes.is_empty()
            && hashes.len() <= 256
            && index < hashes.len()
            && header.prev_block_hash == header::block_id(&parent)
            && parent.height.checked_add(1) == Some(header.height)
            && tx_tree::root_from_hashes(hashes) == header.tx_root,
    )?;
    let (paged_spend, pages, id, fee) = if intent_bytes
        .starts_with(noid_tx::native_assets::wire::NATIVE_INTENT_MAGIC)
    {
        let mut intent = NativeIntent::from_bytes(intent_bytes).map_err(|e| e.to_string())?;
        intent.authorization_bytes.clear();
        let facts = intent.validate_structure().map_err(|e| e.to_string())?;
        let mut bytes = b"NAR1".to_vec();
        bytes.extend_from_slice(header_bytes);
        bytes.extend_from_slice(parent_bytes);
        bytes.extend_from_slice(&intent.to_bytes().map_err(|e| e.to_string())?);
        (bytes, intent.pages, facts.logical_txid.0, facts.fee)
    } else {
        let mut intent = PagedSpendIntent::from_bytes(intent_bytes).map_err(|e| e.to_string())?;
        intent.authorization_bytes.clear();
        let facts = noid_tx::validate_paged_spend(&intent.pages).map_err(|e| e.to_string())?;
        (
            intent.to_bytes().map_err(|e| e.to_string())?,
            intent.pages,
            facts.logical_txid.0,
            facts.fee,
        )
    };
    require(hashes[index] == id)?;
    let receipt = Receipt {
        construction_marker: 2,
        paged_spend,
        tx_index: index as u16,
        tx_count: hashes.len() as u16,
        merkle_path: tx_tree::path_from_hashes(hashes, index),
        claimed_root: header.tx_root,
        claimed_height: header.height,
        summary: Summary {
            logical_txid: id,
            inputs: pages
                .iter()
                .flat_map(|p| {
                    p.body
                        .live_inputs()
                        .map(|(_, i)| (i.slot_index, p.body.input_owner))
                })
                .collect(),
            outputs: pages
                .iter()
                .flat_map(|p| {
                    p.body
                        .live_outputs()
                        .map(|(_, o)| (o.slot_index, o.amount, o.owner))
                })
                .collect(),
            fee_micronoid: fee,
            confirmed_height: header.height,
            confirmed_unix: header.timestamp,
        },
    };
    require(tx_tree::verify_path(
        id,
        &receipt.merkle_path,
        index,
        hashes.len(),
        receipt.claimed_root,
    ))?;
    bincode::serialize(&receipt).map_err(|e| e.to_string())
}
