export type NativeCatalogKind = "markets" | "collections" | "nft_listings";

export interface NativeProtocolInfo {
  tip_height: number;
  activation_height: number | null;
  active_at_next_block: boolean;
  runtime_available: boolean;
  initial_creator_purchase: boolean;
  nft_batch_limit: number | null;
  token_decimals: number;
  minimum_launch_whole_tokens: string;
  maximum_launch_whole_tokens: string;
  minimum_backing_micronoid_per_whole_token: string;
  pages: number | null;
  headers: number | null;
  actions: number | null;
  markets: number | null;
  trade_policies: number | null;
  trade_funding_inputs: number | null;
}

export type NativeRequest =
  | { action: "create_token"; whole_tokens: string; metadata_hash: string; initial_buy_units?: string | null }
  | { action: "transfer_token"; asset_id: string; units: string; recipient: string }
  | { action: "burn_token"; asset_id: string; units: string }
  | { action: "trade"; asset_id: string; buy: boolean; gross_input: string; minimum_output?: string | null; slippage_bps?: number | null; valid_until?: number | null }
  | { action: "create_collection"; maximum_items: string; metadata_hash: string }
  | { action: "mint_nft"; collection_id: string; metadata_hash: string }
  | { action: "mint_nfts"; collection_id: string; metadata_hashes: string[] }
  | { action: "transfer_nft"; collection_id: string; serial: string; recipient: string }
  | { action: "burn_nft"; collection_id: string; serial: string }
  | { action: "list_nft"; collection_id: string; serial: string; ask_micronoid: string; expiry_height: number }
  | { action: "buy_nft"; collection_id: string; serial: string; maximum_ask_micronoid: string }
  | { action: "cancel_listing"; collection_id: string; serial: string };

export interface NativePendingQuote {
  pending_policies: number;
  selected_policies: number;
  selected_markets: number;
  position: number | null;
  output: string | null;
  spent_input: string | null;
  market_fee: string | null;
  network_fee: string | null;
  confirmed_output: string | null;
}

export interface NativeClientReview {
  parent_hash: string;
  state_root: string;
  request: NativeRequest;
  fee_micronoid: string;
  fee_limit_micronoid: string | null;
  noid_debit_micronoid: string;
  noid_credit_micronoid: string;
  reserve_deposit_micronoid: string | null;
  initial_buy_cost_micronoid: string | null;
  redemption_micronoid: string | null;
  quoted_output: string | null;
  minimum_output: string | null;
  valid_until: number | null;
  asset_id: string | null;
  collection_id: string | null;
  serial: string | null;
  last_serial: string | null;
  input_count: number;
  output_count: number;
  pending_quote: NativePendingQuote | null;
}

export interface NativeClientPlan {
  schema_version: 1;
  plan_id: string;
  intent_id: string;
  owner: string;
  candidate_height: number;
  parent_header_hex: string;
  chain_id: string;
  epoch_anchor: string;
  owner_authorization_version: 4;
  intent_kind: "operation" | "trade";
  unsigned_intent_hex: string;
  review: NativeClientReview;
}

export interface NativeHolding {
  root: string;
  kind: number;
  opening_hex: string;
  dependency_hex: string | null;
  slot_index: number;
  creation_id: string;
  amount_micronoid: string;
  unlock_height: number;
  reserved: boolean;
}

export interface NativeWalletCursor {
  owner: string;
  height: number;
  block_hash: string;
  after_root: string | null;
  from_slot: number;
}

export interface NativeHoldingsPage {
  owner: string;
  key_index: number | null;
  height: number;
  block_hash: string;
  state_root: string;
  holdings: NativeHolding[];
  next: NativeWalletCursor | null;
}

export interface NativeCatalogCursor {
  kind: NativeCatalogKind;
  height: number;
  block_hash: string;
  after_key: string;
}

export interface NativeCatalogItem {
  key: string;
  primary: NativeHolding;
  related: NativeHolding[];
}

export interface NativeCatalogPage {
  kind: NativeCatalogKind;
  height: number;
  block_hash: string;
  state_root: string;
  scanned: number;
  items: NativeCatalogItem[];
  next: NativeCatalogCursor | null;
}

export interface NativeMarketDetails {
  height: number;
  block_hash: string;
  state_root: string;
  item: NativeCatalogItem | null;
}

export interface CallOptions { signal?: AbortSignal }
export interface RpcTransport {
  call(method: string, params: readonly unknown[], options?: CallOptions): Promise<unknown>;
}
