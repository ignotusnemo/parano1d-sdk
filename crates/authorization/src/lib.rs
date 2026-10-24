// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

use noid_core::Block128;
use noid_gkr::{
    zk_auth_capsule::ZkAuthCapsuleStateTable,
    zk_authorization::{web3, ZkAuthCapsuleOwnerStatement},
    WalletAuthorizationBundle,
};
use noid_poseidon2b::{
    native::domain::{capacity_iv, TAG_ADDRFIX},
    primitives::{derive_address, Address, SpendSecret},
};
use noid_tx::{
    canonical_paged_spend_auth,
    experimental_object::{ObjectIntent, ObjectOpening},
    PagedSpendIntent, TxPage, TX_BODY_WIRE_SIZE,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

pub type Result<T> = std::result::Result<T, String>;
pub mod history;
pub mod media;
pub mod native;
pub const MAX_OPERATION_BYTES: usize = 768 * 1024;
pub const MAX_JOB_BYTES: usize = MAX_OPERATION_BYTES + web3::MAX_REQUEST_BYTES + 16;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Operation {
    pub pages_hex: String,
    #[serde(default)]
    pub opening_hex: Option<String>,
    #[serde(default)]
    pub call_height: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum WalletOperation {
    Spend(Operation),
    Native(native::NativeOperationPlan),
}

impl From<Operation> for WalletOperation {
    fn from(value: Operation) -> Self {
        Self::Spend(value)
    }
}

impl WalletOperation {
    pub fn statement(&self) -> Result<ZkAuthCapsuleOwnerStatement> {
        match self {
            Self::Spend(o) => o.statement(),
            Self::Native(o) => o.statement(),
        }
    }
    pub fn review(&self) -> Result<serde_json::Value> {
        match self {
            Self::Spend(o) => serde_json::to_value(o.review()?).map_err(|e| e.to_string()),
            Self::Native(o) => o.review(),
        }
    }
    pub fn encode_intent(&self, proof: Vec<u8>) -> Result<Vec<u8>> {
        match self {
            Self::Spend(o) => o.encode_intent(proof),
            Self::Native(o) => o.encode_intent(proof),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct OutputReview {
    pub address: String,
    pub amount_micronoid: String,
    pub slot_index: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct InputReview {
    pub slot_index: u32,
    pub creation_id: String,
    pub amount_micronoid: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct Review {
    pub kind: &'static str,
    pub txid: String,
    pub authority: String,
    pub fee_micronoid: String,
    pub inputs: usize,
    pub input_refs: Vec<InputReview>,
    pub outputs: Vec<OutputReview>,
    pub contract_address: Option<String>,
    pub terminal: Option<bool>,
    pub call_height: Option<String>,
    pub successor_opening_hex: Option<String>,
}

impl Operation {
    pub fn pages(&self) -> Result<Vec<TxPage>> {
        if self.pages_hex.len() > 128 * TX_BODY_WIRE_SIZE * 2 {
            return Err("too many pages".into());
        }
        let bytes = hex::decode(&self.pages_hex).map_err(|_| "invalid page encoding")?;
        if bytes.is_empty() || bytes.len() % TX_BODY_WIRE_SIZE != 0 {
            return Err("invalid page length".into());
        }
        bytes
            .chunks_exact(TX_BODY_WIRE_SIZE)
            .map(|p| TxPage::from_bytes(p).map_err(|e| e.to_string()))
            .collect()
    }

    pub fn opening(&self) -> Result<Option<ObjectOpening>> {
        self.opening_hex
            .as_ref()
            .map(|s| {
                if s.len() != noid_tx::experimental_object::OPENING_BYTES * 2 {
                    return Err("invalid contract opening length".into());
                }
                ObjectOpening::from_bytes(&hex::decode(s).map_err(|_| "invalid contract encoding")?)
                    .map_err(|e| e.to_string())
            })
            .transpose()
    }

    pub fn statement(&self) -> Result<ZkAuthCapsuleOwnerStatement> {
        let pages = self.pages()?;
        let canonical = canonical_paged_spend_auth(&pages).map_err(|e| e.to_string())?;
        let authority = if let Some(opening) = self.opening()? {
            if pages.len() != 1 {
                return Err("contract calls require one page".into());
            }
            let height: u64 = self
                .call_height
                .as_ref()
                .ok_or("missing call height")?
                .parse()
                .map_err(|_| "invalid call height")?;
            opening
                .check_call(&pages[0], height)
                .map_err(|e| e.to_string())?
                .authority
        } else {
            if self.call_height.is_some()
                || pages
                    .iter()
                    .any(|p| p.body.validity_bitmap & noid_tx::PAGED_SPEND_CONTRACT_BIT != 0)
            {
                return Err("contract opening required".into());
            }
            canonical.input_owner
        };
        Ok(ZkAuthCapsuleOwnerStatement {
            tx_body_hash: canonical.logical_txid.as_fields(),
            address: authority.as_fields(),
        })
    }

    pub fn review(&self) -> Result<Review> {
        let statement = self.statement()?;
        let pages = self.pages()?;
        let canonical = canonical_paged_spend_auth(&pages).map_err(|e| e.to_string())?;
        let opening = self.opening()?;
        let checked = if let Some(o) = &opening {
            Some(
                o.check_call(
                    &pages[0],
                    self.call_height
                        .as_ref()
                        .unwrap()
                        .parse()
                        .map_err(|_| "invalid height")?,
                )
                .map_err(|e| e.to_string())?,
            )
        } else {
            None
        };
        let fee = pages
            .iter()
            .try_fold(0u64, |a, p| a.checked_add(p.body.fee))
            .ok_or("fee overflow")?;
        Ok(Review {
            kind: if opening.is_some() {
                "contract"
            } else {
                "payment"
            },
            txid: hex::encode(canonical.logical_txid.0),
            authority: fields_address(statement.address).to_string(),
            fee_micronoid: fee.to_string(),
            inputs: pages.iter().map(|p| p.body.live_input_count()).sum(),
            input_refs: pages
                .iter()
                .flat_map(|p| p.body.live_inputs())
                .map(|(_, i)| InputReview {
                    slot_index: i.slot_index,
                    creation_id: i.creation_id.to_string(),
                    amount_micronoid: i.amount.to_string(),
                })
                .collect(),
            outputs: pages
                .iter()
                .flat_map(|p| p.body.live_outputs())
                .map(|(_, o)| OutputReview {
                    address: o.owner.to_string(),
                    amount_micronoid: o.amount.to_string(),
                    slot_index: o.slot_index,
                })
                .collect(),
            contract_address: opening.as_ref().map(|o| o.root().to_string()),
            terminal: checked.as_ref().map(|c| c.terminal),
            call_height: self.call_height.clone(),
            successor_opening_hex: match (&opening, &checked) {
                (Some(o), Some(c)) if !c.terminal => Some(hex::encode(
                    o.successor(c.next).to_bytes().map_err(|e| e.to_string())?,
                )),
                _ => None,
            },
        })
    }

    pub fn encode_intent(&self, proof: Vec<u8>) -> Result<Vec<u8>> {
        let group = PagedSpendIntent::new(self.pages()?, proof).map_err(|e| e.to_string())?;
        if let Some(opening) = self.opening()? {
            ObjectIntent {
                opening,
                spend: group,
            }
            .to_bytes()
            .map_err(|e| e.to_string())
        } else {
            group.to_bytes().map_err(|e| e.to_string())
        }
    }
}

pub fn fields_address(fields: [Block128; 2]) -> Address {
    let mut bytes = [0; 32];
    bytes[..16].copy_from_slice(&fields[0].0.to_le_bytes());
    bytes[16..].copy_from_slice(&fields[1].0.to_le_bytes());
    Address(bytes)
}

pub struct Prepared {
    inner: web3::Prepared,
}
pub struct Pending {
    operation: WalletOperation,
    inner: web3::Pending,
}

pub fn prepare(secret: &SpendSecret) -> Result<Prepared> {
    let permutation = secret.with_exposed_prover_fields(|fields| {
        let iv = capacity_iv(TAG_ADDRFIX);
        let mut input = [fields[0], fields[1], iv[0], iv[1]];
        let output = noid_gkr::evaluate_permutation(input);
        input.zeroize();
        output
    });
    let state = ZkAuthCapsuleStateTable::from_permutation_witness(&permutation)
        .map_err(|e| format!("{e:?}"))?;
    let inner =
        web3::prepare(&state, derive_address(secret).as_fields()).map_err(|e| format!("{e:?}"))?;
    Ok(Prepared { inner })
}

impl Prepared {
    pub fn begin(self, operation: impl Into<WalletOperation>) -> Result<(Vec<u8>, Pending)> {
        let operation = operation.into();
        let statement = operation.statement()?;
        let encoded = serde_json::to_vec(&operation).map_err(|_| "operation encoding failed")?;
        if encoded.len() > MAX_OPERATION_BYTES {
            return Err("operation too large".into());
        }
        let (proof_request, inner) = self.inner.begin(statement).map_err(|e| format!("{e:?}"))?;
        let mut request = Vec::with_capacity(12 + encoded.len() + proof_request.len());
        request.extend_from_slice(b"N1DWEB34");
        request.extend_from_slice(&(encoded.len() as u32).to_le_bytes());
        request.extend_from_slice(&encoded);
        request.extend_from_slice(&proof_request);
        Ok((request, Pending { operation, inner }))
    }
}

pub fn parse_job(bytes: &[u8]) -> Result<(WalletOperation, &[u8])> {
    if bytes.len() < 12 || bytes.len() > MAX_JOB_BYTES || &bytes[..8] != b"N1DWEB34" {
        return Err("invalid proving request".into());
    }
    let len = u32::from_le_bytes(bytes[8..12].try_into().unwrap()) as usize;
    if len > MAX_OPERATION_BYTES || len > bytes.len() - 12 {
        return Err("invalid operation length".into());
    }
    let operation: WalletOperation =
        serde_json::from_slice(&bytes[12..12 + len]).map_err(|_| "invalid operation")?;
    let request = &bytes[12 + len..];
    if operation.statement()? != web3::request_statement(request).map_err(|e| format!("{e:?}"))? {
        return Err("authorization statement mismatch".into());
    }
    Ok((operation, request))
}

pub fn prove_job(bytes: &[u8]) -> Result<Vec<u8>> {
    let (_, request) = parse_job(bytes)?;
    web3::prove(request).map_err(|e| format!("{e:?}"))
}

impl Pending {
    pub fn finish(self, response: &[u8]) -> Result<Vec<u8>> {
        let proof = self
            .inner
            .finish(response)
            .map_err(|_| "Proving service returned an invalid authorization proof".to_owned())?;
        let bundle = WalletAuthorizationBundle { proof }
            .to_bytes()
            .map_err(|e| e.to_string())?;
        self.operation.encode_intent(bundle)
    }
}

pub fn verify_intent(bytes: &[u8], height: u64) -> Result<String> {
    let (pages, bundle, opening) = if bytes.starts_with(noid_tx::experimental_object::INTENT_MAGIC)
    {
        let i = ObjectIntent::from_bytes(bytes).map_err(|e| e.to_string())?;
        (i.spend.pages, i.spend.authorization_bytes, Some(i.opening))
    } else {
        let i = PagedSpendIntent::from_bytes(bytes).map_err(|e| e.to_string())?;
        (i.pages, i.authorization_bytes, None)
    };
    let bundle = WalletAuthorizationBundle::from_bytes(&bundle).map_err(|e| e.to_string())?;
    if let Some(opening) = opening {
        noid_gkr::wallet_authorization::verify_experimental_object_authorization(
            &pages[0], &opening, height, &bundle,
        )
        .map_err(|e| e.to_string())?;
    } else {
        noid_gkr::verify_paged_spend_authorization(&pages, &bundle).map_err(|e| e.to_string())?;
    }
    Ok(hex::encode(
        canonical_paged_spend_auth(&pages)
            .map_err(|e| e.to_string())?
            .logical_txid
            .0,
    ))
}
