// SPDX-License-Identifier: Apache-2.0

pub mod header;
pub mod receipt;
mod tx_tree;
pub mod types;
pub mod view;

use crate::{Result, ZkAuthCapsuleOwnerStatement};
use noid_poseidon2b::primitives::Address;
use noid_tx::native_assets::{
    financial::FinancialOperation,
    launch::LaunchSide,
    nft_market::{ListingDefinition, NftMarketOpening, NftRoundContext, NFT_FEE_CREDIT},
    trade::wire::TradeOwnerIntent,
    transition::NativeOperation,
    wire::NativeIntent,
    AssetId, CollectionId, NativeOpening, NftItem, TOKEN_UNITS,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use types::{NativeClientIntentKind, NativeClientPlan, NativeWalletRequest};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NativeOperationPlan {
    pub native_plan: NativeClientPlan,
    pub expected_request: NativeWalletRequest,
    pub expected_chain: String,
    pub expected_parent_hash: String,
    pub maximum_fee_micronoid: String,
}

fn hash(value: &str) -> Result<[u8; 32]> {
    if value.len() != 64 {
        return Err("Invalid 32-byte identity".into());
    }
    hex::decode(value)
        .map_err(|_| "Invalid identity encoding".to_owned())?
        .try_into()
        .map_err(|_| "Invalid identity length".into())
}

fn integer(value: &str) -> Result<u64> {
    let n: u64 = value.parse().map_err(|_| "Invalid exact integer")?;
    if n.to_string() != value {
        return Err("Expected a canonical decimal integer".into());
    }
    Ok(n)
}

fn require(condition: bool) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err("Native operation differs from the approved terms".into())
    }
}

fn same_item(item: NftItem, collection: &str, serial: &str) -> Result<()> {
    require(item.collection.0 == hash(collection)? && item.serial == integer(serial)?)
}

impl NativeOperationPlan {
    fn context(&self) -> Result<(header::BlockHeader, Address, [u8; 32], [u8; 32], Vec<u8>)> {
        let p = &self.native_plan;
        require(p.schema_version == 1 && p.owner_authorization_version == 4)?;
        let parent_bytes =
            hex::decode(&p.parent_header_hex).map_err(|_| "Invalid parent header")?;
        let parent = header::BlockHeader::from_bytes(&parent_bytes)?;
        let parent_id = header::block_id(&parent);
        let owner = Address::parse(&p.owner).map_err(|e| e.to_string())?;
        let chain = hash(&self.expected_chain)?;
        let epoch = hash(&p.epoch_anchor)?;
        require(
            chain == hash(&p.chain_id)?
                && parent_id == hash(&p.review.parent_hash)?
                && parent_id == hash(&self.expected_parent_hash)?
                && parent.state_root == hash(&p.review.state_root)?
                && parent.height.checked_add(1) == Some(p.candidate_height)
                && p.review.request == self.expected_request,
        )?;
        let request = serde_json::to_vec(&self.expected_request).map_err(|e| e.to_string())?;
        require(request.len() <= 32 * 1024 && p.unsigned_intent_hex.len() <= 512 * 1024)?;
        let bytes = hex::decode(&p.unsigned_intent_hex).map_err(|_| "Invalid native intent")?;
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"NOIDNativeClientPlan1");
        hasher.update(&parent_bytes);
        hasher.update(&owner.0);
        hasher.update(&epoch);
        hasher.update(&(request.len() as u32).to_le_bytes());
        hasher.update(&request);
        hasher.update(&bytes);
        require(hasher.finalize().as_bytes() == &hash(&p.plan_id)?)?;
        Ok((parent, owner, chain, epoch, bytes))
    }

    pub fn statement(&self) -> Result<ZkAuthCapsuleOwnerStatement> {
        let (parent, owner, chain, epoch, bytes) = self.context()?;
        let p = &self.native_plan;
        let auth = match p.intent_kind {
            NativeClientIntentKind::Operation => {
                let intent = NativeIntent::from_bytes(&bytes).map_err(|e| e.to_string())?;
                require(intent.authorization_bytes.is_empty())?;
                let pages = intent.validate_structure().map_err(|e| e.to_string())?;
                require(
                    pages.authority == owner
                        && pages.epoch_anchor == epoch
                        && pages.operation.enabled()
                        && pages.operation.requires_owner(),
                )?;
                let facts = if matches!(pages.operation, NativeOperation::Financial(_)) {
                    intent.checked_financial_owner(
                        chain,
                        NftRoundContext::new(
                            p.candidate_height,
                            header::block_id(&parent),
                            parent.alloc_counter,
                        )
                        .map_err(|e| e.to_string())?,
                    )
                } else {
                    intent.checked(chain, p.candidate_height)
                }
                .map_err(|e| e.to_string())?;
                self.check_operation(&intent, &facts, owner)?;
                facts.pages.canonical_auth()
            }
            NativeClientIntentKind::Trade => {
                let intent = TradeOwnerIntent::from_bytes(&bytes).map_err(|e| e.to_string())?;
                require(intent.authorization_bytes.is_empty())?;
                intent
                    .intent
                    .checked(chain, epoch, p.candidate_height)
                    .map_err(|e| e.to_string())?;
                self.check_trade(&intent, owner)?;
                intent.intent.canonical_auth().map_err(|e| e.to_string())?
            }
        };
        require(auth.input_owner == owner && auth.tx_body_hash.0 == hash(&p.intent_id)?)?;
        Ok(ZkAuthCapsuleOwnerStatement {
            tx_body_hash: auth.tx_body_hash.as_fields(),
            address: owner.as_fields(),
        })
    }

    fn check_trade(&self, wire: &TradeOwnerIntent, owner: Address) -> Result<()> {
        let NativeWalletRequest::Trade {
            asset_id,
            buy,
            gross_input,
            minimum_output,
            slippage_bps,
            valid_until,
        } = &self.expected_request
        else {
            return Err("Expected an operation intent".into());
        };
        let t = &wire.intent;
        let p = t.policy;
        let r = &self.native_plan.review;
        require(
            p.owner == owner
                && p.recipient == owner
                && p.asset.0 == hash(asset_id)?
                && (p.side == LaunchSide::Buy) == *buy
                && p.gross_input == integer(gross_input)?
                && p.valid_from == self.native_plan.candidate_height
                && p.valid_until == valid_until.unwrap_or(p.valid_from.saturating_add(3))
                && p.fee_limit
                    == integer(
                        r.fee_limit_micronoid
                            .as_deref()
                            .ok_or("Missing fee limit")?,
                    )?
                && p.fee_limit <= integer(&self.maximum_fee_micronoid)?
                && r.minimum_output.as_deref().map(integer).transpose()? == Some(p.minimum_output)
                && r.valid_until == Some(p.valid_until)
                && r.input_count == t.funding.len()
                && r.output_count == 0,
        )?;
        let quote = integer(r.quoted_output.as_deref().ok_or("Missing trade quote")?)?;
        if let Some(minimum) = minimum_output {
            require(p.minimum_output == integer(minimum)?)?;
        } else {
            let bps = slippage_bps.unwrap_or(100);
            require(bps < 10_000)?;
            let minimum =
                ((u128::from(quote) * u128::from(10_000 - bps)).div_ceil(10_000) as u64).max(1);
            require(p.minimum_output >= minimum && p.minimum_output <= quote)?;
        }
        require(integer(&r.fee_micronoid)? <= p.fee_limit)?;
        for claim in &t.funding {
            require(match claim.opening {
                None => claim.root == owner,
                Some(NativeOpening::TokenBalance(b)) => {
                    !*buy && b.owner == owner && b.asset == p.asset
                }
                _ => false,
            })?;
        }
        Ok(())
    }

    fn check_operation(
        &self,
        intent: &NativeIntent,
        f: &noid_tx::native_assets::wire::NativeSpendFacts,
        owner: Address,
    ) -> Result<()> {
        let r = &self.native_plan.review;
        let output = &f.outputs;
        let native = output.iter().filter_map(|o| o.opening).collect::<Vec<_>>();
        let input = f
            .inputs
            .iter()
            .filter_map(|i| i.opening)
            .collect::<Vec<_>>();
        let spent = f
            .inputs
            .iter()
            .filter(|i| i.opening.is_none())
            .map(|i| u128::from(i.input.amount))
            .sum::<u128>();
        let received = output
            .iter()
            .filter(|o| o.opening.is_none() && o.output.owner == owner)
            .map(|o| u128::from(o.output.amount))
            .sum::<u128>();
        require(
            f.inputs
                .iter()
                .filter(|i| i.opening.is_none())
                .all(|i| i.root == owner)
                && r.input_count == f.inputs.len()
                && r.output_count == output.len()
                && integer(&r.fee_micronoid)? == f.pages.fee
                && f.pages.fee <= integer(&self.maximum_fee_micronoid)?
                && u128::from(integer(&r.noid_debit_micronoid)?) == spent.saturating_sub(received)
                && u128::from(integer(&r.noid_credit_micronoid)?) == received.saturating_sub(spent),
        )?;
        let mut seller_payment = None;
        match &self.expected_request {
            NativeWalletRequest::CreateToken {
                whole_tokens,
                metadata_hash,
                initial_buy_units,
            } => {
                require(matches!(
                    f.pages.operation,
                    NativeOperation::Financial(FinancialOperation::CreateLaunch { .. })
                ))?;
                let definition = native
                    .iter()
                    .find_map(|o| {
                        if let NativeOpening::FungibleDefinition(d) = o {
                            Some(*d)
                        } else {
                            None
                        }
                    })
                    .ok_or("Missing token definition")?;
                let reserve = native
                    .iter()
                    .find_map(|o| {
                        if let NativeOpening::TokenReserve(d) = o {
                            Some(*d)
                        } else {
                            None
                        }
                    })
                    .ok_or("Missing token reserve")?;
                let supply = integer(whole_tokens)?
                    .checked_mul(TOKEN_UNITS)
                    .ok_or("Token supply overflow")?;
                let buy = initial_buy_units
                    .as_deref()
                    .map(integer)
                    .transpose()?
                    .unwrap_or(0);
                let balances = native
                    .iter()
                    .filter_map(|o| {
                        if let NativeOpening::TokenBalance(b) = o {
                            Some(*b)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                let cost = noid_tx::native_assets::launch::curve_cash_for_supply(supply, buy)
                    .map_err(|e| e.to_string())?;
                require(
                    definition.issuer == owner
                        && definition.metadata == hash(metadata_hash)?
                        && definition.initial_supply == supply
                        && reserve.asset == definition.asset
                        && reserve.outstanding_units == supply
                        && reserve.reserve_micronoid
                            == integer(
                                r.reserve_deposit_micronoid
                                    .as_deref()
                                    .ok_or("Missing reserve deposit")?,
                            )?
                        && cost
                            == integer(
                                r.initial_buy_cost_micronoid
                                    .as_deref()
                                    .ok_or("Missing creator purchase cost")?,
                            )?
                        && r.asset_id.as_deref().map(hash).transpose()? == Some(definition.asset.0)
                        && balances.len() == usize::from(buy != 0)
                        && native.len() == 3 + balances.len()
                        && balances.iter().all(|b| {
                            b.owner == owner && b.asset == definition.asset && b.units == buy
                        }),
                )?;
            }
            NativeWalletRequest::TransferToken {
                asset_id,
                units,
                recipient,
            } => {
                let asset = AssetId(hash(asset_id)?);
                let recipient = Address::parse(recipient).map_err(|e| e.to_string())?;
                require(f.pages.operation == NativeOperation::TransferToken { asset })?;
                let balances = native
                    .iter()
                    .map(|o| {
                        if let NativeOpening::TokenBalance(b) = o {
                            Ok(*b)
                        } else {
                            Err("Unexpected native output".to_owned())
                        }
                    })
                    .collect::<Result<Vec<_>>>()?;
                require(
                    !balances.is_empty()
                        && balances[0].owner == recipient
                        && balances[0].units == integer(units)?
                        && balances.iter().all(|b| b.asset == asset)
                        && balances.iter().skip(1).all(|b| b.owner == owner),
                )?;
            }
            NativeWalletRequest::BurnToken { asset_id, units } => {
                let asset = AssetId(hash(asset_id)?);
                require(
                    f.pages.operation == NativeOperation::RedeemToken { asset }
                        && f.transition.redeemed_units == integer(units)?
                        && Some(f.transition.redemption_micronoid)
                            == r.redemption_micronoid.as_deref().map(integer).transpose()?,
                )?;
                require(native.iter().all(|o| matches!(o, NativeOpening::TokenReserve(v) if v.asset == asset)
                    || matches!(o, NativeOpening::TokenBalance(b) if b.asset == asset && b.owner == owner)))?;
            }
            NativeWalletRequest::CreateCollection {
                maximum_items,
                metadata_hash,
            } => {
                require(
                    matches!(f.pages.operation, NativeOperation::CreateCollection { .. })
                        && native.len() == 1,
                )?;
                let NativeOpening::NftCollection(c) = native[0] else {
                    return Err("Missing collection".into());
                };
                require(
                    c.creator == owner
                        && c.issued_items == 0
                        && c.maximum_items == integer(maximum_items)?
                        && c.metadata == hash(metadata_hash)?
                        && r.collection_id.as_deref().map(hash).transpose()?
                            == Some(c.collection.0),
                )?;
            }
            NativeWalletRequest::MintNft {
                collection_id,
                metadata_hash,
            } => {
                check_mint(f, owner, collection_id, std::slice::from_ref(metadata_hash))?;
            }
            NativeWalletRequest::MintNfts {
                collection_id,
                metadata_hashes,
            } => {
                check_mint(f, owner, collection_id, metadata_hashes)?;
            }
            NativeWalletRequest::TransferNft {
                collection_id,
                serial,
                recipient,
            } => {
                require(f.pages.operation == NativeOperation::TransferNft && native.len() == 1)?;
                let NativeOpening::NftItem(item) = native[0] else {
                    return Err("Missing transferred NFT".into());
                };
                same_item(item, collection_id, serial)?;
                require(item.owner == Address::parse(recipient).map_err(|e| e.to_string())?)?;
            }
            NativeWalletRequest::BurnNft {
                collection_id,
                serial,
            } => {
                require(f.pages.operation == NativeOperation::BurnNft && native.is_empty())?;
                let item = input
                    .iter()
                    .find_map(|o| {
                        if let NativeOpening::NftItem(i) = o {
                            Some(*i)
                        } else {
                            None
                        }
                    })
                    .ok_or("Missing NFT input")?;
                same_item(item, collection_id, serial)?;
            }
            NativeWalletRequest::ListNft {
                collection_id,
                serial,
                ask_micronoid,
                expiry_height,
            } => {
                require(matches!(
                    f.pages.operation,
                    NativeOperation::Financial(FinancialOperation::CreateListing { .. })
                ))?;
                let definition = listing(intent)?;
                require(
                    definition.collection.0 == hash(collection_id)?
                        && definition.serial == integer(serial)?
                        && definition.seller == owner
                        && definition.ask == integer(ask_micronoid)?
                        && definition.expiry_height == *expiry_height,
                )?;
            }
            NativeWalletRequest::BuyNft {
                collection_id,
                serial,
                maximum_ask_micronoid,
            } => {
                require(
                    matches!(
                        f.pages.operation,
                        NativeOperation::Financial(FinancialOperation::Purchase { .. })
                    ) && native.len() == 1,
                )?;
                let definition = listing(intent)?;
                let NativeOpening::NftItem(item) = native[0] else {
                    return Err("Missing purchased NFT".into());
                };
                same_item(item, collection_id, serial)?;
                require(item.owner == owner && definition.ask <= integer(maximum_ask_micronoid)?)?;
                let payment = definition
                    .ask
                    .checked_add(NFT_FEE_CREDIT)
                    .ok_or("NFT payment overflow")?;
                require(output.iter().any(|o| {
                    o.opening.is_none()
                        && o.output.owner == definition.seller
                        && o.output.amount == payment
                }))?;
                seller_payment = Some((definition.seller, payment));
            }
            NativeWalletRequest::CancelListing {
                collection_id,
                serial,
            } => {
                require(
                    matches!(
                        f.pages.operation,
                        NativeOperation::Financial(FinancialOperation::CancelListing)
                    ) && native.len() == 1,
                )?;
                let NativeOpening::NftItem(item) = native[0] else {
                    return Err("Missing returned NFT".into());
                };
                same_item(item, collection_id, serial)?;
                require(item.owner == owner)?;
            }
            NativeWalletRequest::Trade { .. } => return Err("Expected a trade intent".into()),
        }
        require(output.iter().filter(|o| o.opening.is_none()).all(|o| {
            o.output.owner == owner || seller_payment == Some((o.output.owner, o.output.amount))
        }))?;
        Ok(())
    }

    pub fn review(&self) -> Result<Value> {
        self.statement()?;
        let p = &self.native_plan;
        let mut value = serde_json::to_value(&p.review).map_err(|e| e.to_string())?;
        let object = value.as_object_mut().ok_or("Invalid native review")?;
        object.insert(
            "kind".into(),
            json!(if p.intent_kind == NativeClientIntentKind::Trade {
                "trade"
            } else {
                "native"
            }),
        );
        object.insert("authority".into(), json!(p.owner));
        object.insert("txid".into(), json!(p.intent_id));
        object.insert("candidate_height".into(), json!(p.candidate_height));
        Ok(value)
    }

    pub fn encode_intent(&self, proof: Vec<u8>) -> Result<Vec<u8>> {
        self.statement()?;
        let bytes = hex::decode(&self.native_plan.unsigned_intent_hex)
            .map_err(|_| "Invalid native intent")?;
        match self.native_plan.intent_kind {
            NativeClientIntentKind::Operation => {
                let mut intent = NativeIntent::from_bytes(&bytes).map_err(|e| e.to_string())?;
                intent.authorization_bytes = proof;
                intent.to_bytes().map_err(|e| e.to_string())
            }
            NativeClientIntentKind::Trade => {
                let mut intent = TradeOwnerIntent::from_bytes(&bytes).map_err(|e| e.to_string())?;
                intent.authorization_bytes = proof;
                intent.to_bytes().map_err(|e| e.to_string())
            }
        }
    }
}

fn listing(intent: &NativeIntent) -> Result<ListingDefinition> {
    intent
        .dependencies
        .iter()
        .find_map(|o| {
            if let NativeOpening::NftMarket(NftMarketOpening::Definition(d)) = o {
                Some(*d)
            } else {
                None
            }
        })
        .ok_or_else(|| "Missing NFT listing terms".into())
}

fn check_mint(
    f: &noid_tx::native_assets::wire::NativeSpendFacts,
    owner: Address,
    collection: &str,
    hashes: &[String],
) -> Result<()> {
    let collection = CollectionId(hash(collection)?);
    require(f.pages.operation == NativeOperation::MintNft && !hashes.is_empty())?;
    let old = f
        .inputs
        .iter()
        .find_map(|i| {
            if let Some(NativeOpening::NftCollection(c)) = i.opening {
                Some(c)
            } else {
                None
            }
        })
        .ok_or("Missing collection input")?;
    let native = f
        .outputs
        .iter()
        .filter_map(|o| o.opening)
        .collect::<Vec<_>>();
    let items = native
        .iter()
        .filter_map(|o| {
            if let NativeOpening::NftItem(i) = o {
                Some(*i)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    require(
        old.collection == collection
            && old.creator == owner
            && items.len() == hashes.len()
            && native.len() == items.len() + 1,
    )?;
    for (index, (item, metadata)) in items.iter().zip(hashes).enumerate() {
        require(
            item.collection == collection
                && item.owner == owner
                && item.metadata == hash(metadata)?
                && old.issued_items.checked_add(index as u64 + 1) == Some(item.serial),
        )?;
    }
    Ok(())
}
