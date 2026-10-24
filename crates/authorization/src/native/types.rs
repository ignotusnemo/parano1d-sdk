// SPDX-License-Identifier: Apache-2.0

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum NativeWalletRequest {
    TransferToken {
        asset_id: String,
        units: String,
        recipient: String,
    },
    BurnToken {
        asset_id: String,
        units: String,
    },
    Trade {
        asset_id: String,
        buy: bool,
        gross_input: String,
        minimum_output: Option<String>,
        slippage_bps: Option<u16>,
        valid_until: Option<u64>,
    },
    CreateToken {
        whole_tokens: String,
        metadata_hash: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        initial_buy_units: Option<String>,
    },
    CreateCollection {
        maximum_items: String,
        metadata_hash: String,
    },
    MintNft {
        collection_id: String,
        metadata_hash: String,
    },
    MintNfts {
        collection_id: String,
        metadata_hashes: Vec<String>,
    },
    TransferNft {
        collection_id: String,
        serial: String,
        recipient: String,
    },
    BurnNft {
        collection_id: String,
        serial: String,
    },
    ListNft {
        collection_id: String,
        serial: String,
        ask_micronoid: String,
        expiry_height: u64,
    },
    BuyNft {
        collection_id: String,
        serial: String,
        maximum_ask_micronoid: String,
    },
    CancelListing {
        collection_id: String,
        serial: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativePendingQuote {
    pub pending_policies: usize,
    pub selected_policies: usize,
    pub selected_markets: usize,
    pub position: Option<usize>,
    pub output: Option<String>,
    pub spent_input: Option<String>,
    pub market_fee: Option<String>,
    pub network_fee: Option<String>,
    pub confirmed_output: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeClientIntentKind {
    Operation,
    Trade,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeClientPlan {
    pub schema_version: u16,
    pub plan_id: String,
    pub intent_id: String,
    pub owner: String,
    pub candidate_height: u64,
    pub parent_header_hex: String,
    pub chain_id: String,
    pub epoch_anchor: String,
    pub owner_authorization_version: u8,
    pub intent_kind: NativeClientIntentKind,
    pub unsigned_intent_hex: String,
    pub review: NativeClientReview,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeClientReview {
    pub parent_hash: String,
    pub state_root: String,
    pub request: NativeWalletRequest,
    pub fee_micronoid: String,
    pub fee_limit_micronoid: Option<String>,
    pub noid_debit_micronoid: String,
    pub noid_credit_micronoid: String,
    pub reserve_deposit_micronoid: Option<String>,
    pub initial_buy_cost_micronoid: Option<String>,
    pub redemption_micronoid: Option<String>,
    pub quoted_output: Option<String>,
    pub minimum_output: Option<String>,
    pub valid_until: Option<u64>,
    pub asset_id: Option<String>,
    pub collection_id: Option<String>,
    pub serial: Option<String>,
    pub last_serial: Option<String>,
    pub input_count: usize,
    pub output_count: usize,
    pub pending_quote: Option<NativePendingQuote>,
}
