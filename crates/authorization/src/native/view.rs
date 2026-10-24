// SPDX-License-Identifier: Apache-2.0

use super::*;
use noid_tx::{
    native_assets::{launch::LaunchOpening, market::MarketOpening},
    TxInput,
};

pub fn inspect_holding(value: &Value) -> Result<Value> {
    let encoded = value["opening_hex"]
        .as_str()
        .ok_or("Missing native opening")?;
    require(encoded.len() <= noid_tx::native_assets::MAX_NATIVE_OPENING_BYTES * 2)?;
    let opening =
        NativeOpening::from_bytes(&hex::decode(encoded).map_err(|_| "Invalid native opening")?)
            .map_err(|e| e.to_string())?;
    require(
        opening.root().0 == hash(value["root"].as_str().ok_or("Missing native root")?)?
            && value["kind"].as_u64() == Some(opening.kind() as u64),
    )?;
    let dependency = value["dependency_hex"]
        .as_str()
        .map(|s| -> Result<NativeOpening> {
            require(s.len() <= noid_tx::native_assets::MAX_NATIVE_OPENING_BYTES * 2)?;
            NativeOpening::from_bytes(&hex::decode(s).map_err(|_| "Invalid native dependency")?)
                .map_err(|e| e.to_string())
        })
        .transpose()?;
    opening
        .check_dependency(dependency)
        .map_err(|e| e.to_string())?;
    opening
        .check_input_binding(
            &TxInput {
                slot_index: value["slot_index"]
                    .as_u64()
                    .and_then(|v| u32::try_from(v).ok())
                    .ok_or("Invalid native slot")?,
                amount: integer(
                    value["amount_micronoid"]
                        .as_str()
                        .ok_or("Missing native value")?,
                )?,
                creation_id: integer(
                    value["creation_id"]
                        .as_str()
                        .ok_or("Missing native creation ID")?,
                )?,
            },
            opening.root(),
        )
        .map_err(|e| e.to_string())?;
    let mut view = match opening {
        NativeOpening::FungibleDefinition(d) => {
            json!({"type":"token_definition","asset_id":hex::encode(d.asset.0),"creator":d.issuer.to_string(),"supply":d.initial_supply.to_string(),"metadata_hash":hex::encode(d.metadata)})
        }
        NativeOpening::TokenBalance(b) => {
            json!({"type":"token","asset_id":hex::encode(b.asset.0),"owner":b.owner.to_string(),"units":b.units.to_string()})
        }
        NativeOpening::TokenReserve(r) => {
            json!({"type":"reserve","asset_id":hex::encode(r.asset.0),"reserve_micronoid":r.reserve_micronoid.to_string(),"outstanding_units":r.outstanding_units.to_string()})
        }
        NativeOpening::NftCollection(c) => {
            json!({"type":"collection","collection_id":hex::encode(c.collection.0),"creator":c.creator.to_string(),"maximum_items":c.maximum_items.to_string(),"issued_items":c.issued_items.to_string(),"metadata_hash":hex::encode(c.metadata)})
        }
        NativeOpening::NftItem(i) => {
            json!({"type":"nft","collection_id":hex::encode(i.collection.0),"serial":i.serial.to_string(),"owner":i.owner.to_string(),"metadata_hash":hex::encode(i.metadata)})
        }
        NativeOpening::Launch(LaunchOpening::State(s)) => {
            let Some(NativeOpening::Launch(LaunchOpening::Definition(d))) = dependency else {
                return Err("Missing curve definition".into());
            };
            let sold = d
                .initial_supply
                .checked_sub(s.inventory_units)
                .ok_or("Invalid curve inventory")?;
            let price = d.marginal_price(sold).map_err(|e| e.to_string())?;
            json!({"type":"curve","asset_id":hex::encode(d.asset.0),"sold_units":sold.to_string(),"supply":d.initial_supply.to_string(),"sale_units":d.sale_units().to_string(),"cash_micronoid":s.market_noid.to_string(),"graduation_cash_micronoid":d.graduation_cash().to_string(),"price_numerator":price.numerator.to_string(),"price_denominator":price.denominator.to_string()})
        }
        NativeOpening::Market(MarketOpening::Pool(p)) => {
            let Some(NativeOpening::Market(MarketOpening::Definition(d))) = dependency else {
                return Err("Missing DEX definition".into());
            };
            json!({"type":"dex","asset_id":hex::encode(d.quote.0),"base_reserve":p.base_reserve.to_string(),"quote_reserve":p.quote_reserve.to_string(),"permanent_liquidity":p.total_shares == p.locked_shares,"price_numerator":p.base_reserve.to_string(),"price_denominator":p.quote_reserve.to_string()})
        }
        NativeOpening::NftMarket(NftMarketOpening::Listing(_)) => {
            let Some(NativeOpening::NftMarket(NftMarketOpening::Definition(d))) = dependency else {
                return Err("Missing NFT listing definition".into());
            };
            json!({"type":"listing","collection_id":hex::encode(d.collection.0),"serial":d.serial.to_string(),"seller":d.seller.to_string(),"ask_micronoid":d.ask.to_string(),"expiry_height":d.expiry_height.to_string(),"metadata_hash":hex::encode(d.metadata)})
        }
        _ => return Err("Unsupported discovery opening".into()),
    };
    view["root"] = value["root"].clone();
    let creation_id = integer(value["creation_id"].as_str().ok_or("Missing creation ID")?)?;
    view["sequence"] = json!((creation_id & !(1u64 << 63)).to_string());
    view["unlock_height"] = json!(opening.unlock_height().to_string());
    view["reserved"] = json!(value["reserved"].as_bool().unwrap_or(false));
    Ok(view)
}

pub fn inspect_items(value: &Value) -> Result<Value> {
    let items = value["items"].as_array().ok_or("Missing discovery items")?;
    require(items.len() <= 256)?;
    let mut result = Vec::with_capacity(items.len());
    for item in items {
        let mut primary = inspect_holding(&item["primary"])?;
        if let Some(related) = item["related"].as_array() {
            require(related.len() <= 8)?;
            for related in related {
                let terms = inspect_holding(related)?;
                if terms["type"] == "token_definition" {
                    require(terms["asset_id"] == primary["asset_id"])?;
                    primary["created_sequence"] = terms["sequence"].clone();
                    for key in ["metadata_hash", "creator", "supply"] {
                        primary[key] = terms[key].clone();
                    }
                }
                if terms["type"] == "reserve" {
                    require(terms["asset_id"] == primary["asset_id"])?;
                    for key in ["reserve_micronoid", "outstanding_units"] {
                        primary[key] = terms[key].clone();
                    }
                }
            }
        }
        result.push(primary);
    }
    Ok(Value::Array(result))
}
