import { integerString } from "./amounts.js";
import { ProtocolError } from "./rpc.js";
import type { CallOptions, NativeCatalogCursor, NativeCatalogKind, NativeCatalogPage,
  NativeClientPlan, NativeHoldingsPage, NativeMarketDetails, NativeProtocolInfo,
  NativeRequest, NativeWalletCursor, RpcTransport } from "./types.js";

export const MAINNET_ACTIVATION_HEIGHT = 279_370;
export const OWNER_AUTHORIZATION_VERSION = 4;
export const UPSTREAM_COMMIT = "848209d5db75137483cb41a94b310ad11463473f";

function record(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new ProtocolError("Expected an RPC object");
  return value as Record<string, unknown>;
}

function height(value: unknown): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) throw new ProtocolError("Invalid exact height or count");
  return value;
}

function digest(value: unknown): string {
  if (typeof value !== "string" || !/^[a-fA-F0-9]{64}$/.test(value)) throw new ProtocolError("Expected a 32-byte hexadecimal identity");
  return value.toLowerCase();
}

function owner(value: unknown): string {
  if (typeof value !== "string" || value.length < 8 || value.length > 128 || !/^o1[a-z0-9]+$/.test(value)) {
    throw new ProtocolError("Expected an o1 owner address");
  }
  return value;
}

function amount(value: unknown): string {
  if (typeof value !== "string") throw new ProtocolError("RPC amounts require decimal strings");
  return integerString(value);
}

function positive(value: unknown): string {
  const result = amount(value);
  if (result === "0") throw new ProtocolError("Operation amount must be positive");
  return result;
}

export function canonicalNativeRequest(input: NativeRequest): NativeRequest {
  const r = record(input);
  const action = r.action;
  let out: NativeRequest;
  switch (action) {
    case "create_token":
      out = { action, whole_tokens: positive(r.whole_tokens), metadata_hash: digest(r.metadata_hash) };
      if (r.initial_buy_units != null) out.initial_buy_units = amount(r.initial_buy_units);
      break;
    case "transfer_token": out = { action, asset_id: digest(r.asset_id), units: positive(r.units), recipient: owner(r.recipient) }; break;
    case "burn_token": out = { action, asset_id: digest(r.asset_id), units: positive(r.units) }; break;
    case "trade": {
      if (typeof r.buy !== "boolean") throw new ProtocolError("Trade side must be boolean");
      const slippage = r.slippage_bps == null ? null : height(r.slippage_bps);
      if (slippage != null && slippage > 10_000) throw new ProtocolError("Slippage exceeds 10000 basis points");
      out = { action, asset_id: digest(r.asset_id), buy: r.buy, gross_input: positive(r.gross_input),
        minimum_output: r.minimum_output == null ? null : amount(r.minimum_output), slippage_bps: slippage,
        valid_until: r.valid_until == null ? null : height(r.valid_until) };
      break;
    }
    case "create_collection": out = { action, maximum_items: positive(r.maximum_items), metadata_hash: digest(r.metadata_hash) }; break;
    case "mint_nft": out = { action, collection_id: digest(r.collection_id), metadata_hash: digest(r.metadata_hash) }; break;
    case "mint_nfts": {
      if (!Array.isArray(r.metadata_hashes) || r.metadata_hashes.length === 0 || r.metadata_hashes.length > 128) throw new ProtocolError("Invalid NFT batch length");
      out = { action, collection_id: digest(r.collection_id), metadata_hashes: r.metadata_hashes.map(digest) };
      break;
    }
    case "transfer_nft": out = { action, collection_id: digest(r.collection_id), serial: positive(r.serial), recipient: owner(r.recipient) }; break;
    case "burn_nft": out = { action, collection_id: digest(r.collection_id), serial: positive(r.serial) }; break;
    case "list_nft": out = { action, collection_id: digest(r.collection_id), serial: positive(r.serial), ask_micronoid: positive(r.ask_micronoid), expiry_height: height(r.expiry_height) }; break;
    case "buy_nft": out = { action, collection_id: digest(r.collection_id), serial: positive(r.serial), maximum_ask_micronoid: positive(r.maximum_ask_micronoid) }; break;
    case "cancel_listing": out = { action, collection_id: digest(r.collection_id), serial: positive(r.serial) }; break;
    default: throw new ProtocolError("Unsupported native action");
  }
  const permitted = new Set(Object.keys(out));
  if (action === "create_token") permitted.add("initial_buy_units");
  if (Object.keys(r).some(key => !permitted.has(key))) throw new ProtocolError("Unknown native request field");
  if (new TextEncoder().encode(JSON.stringify(out)).length > 32 * 1024) throw new ProtocolError("Native request exceeds 32 KiB");
  return out;
}

export class ActivationPendingError extends Error {
  constructor(public readonly protocol: NativeProtocolInfo) {
    super(`Native operations activate at candidate block ${protocol.activation_height ?? "unscheduled"}`);
    this.name = "ActivationPendingError";
  }
}

export interface NativeClientOptions { expectedChainId?: string }

export class NativeClient {
  private readonly expectedChainId: string | undefined;
  constructor(readonly transport: RpcTransport, options: NativeClientOptions = {}) {
    this.expectedChainId = options.expectedChainId === undefined ? undefined : digest(options.expectedChainId);
  }

  async getProtocol(options?: CallOptions): Promise<NativeProtocolInfo> {
    const p = record(await this.transport.call("paranoid_getNativeProtocol", [], options));
    height(p.tip_height);
    if (p.activation_height != null) height(p.activation_height);
    if (typeof p.active_at_next_block !== "boolean" || typeof p.runtime_available !== "boolean" || p.token_decimals !== 6) {
      throw new ProtocolError("Unsupported native protocol response");
    }
    for (const field of ["minimum_launch_whole_tokens", "maximum_launch_whole_tokens", "minimum_backing_micronoid_per_whole_token"]) amount(p[field]);
    return p as unknown as NativeProtocolInfo;
  }

  private async active(options?: CallOptions): Promise<NativeProtocolInfo> {
    const p = await this.getProtocol(options);
    if (!p.active_at_next_block) throw new ActivationPendingError(p);
    if (!p.runtime_available) throw new ProtocolError("Native runtime is unavailable");
    if (p.activation_height == null || p.tip_height + 1 < p.activation_height) throw new ProtocolError("Inconsistent native activation context");
    return p;
  }

  async getHoldings(address: string, cursor: NativeWalletCursor | null = null, limit = 128, options?: CallOptions): Promise<NativeHoldingsPage> {
    owner(address); this.limit(limit);
    if (cursor && cursor.owner !== address) throw new ProtocolError("Holdings cursor belongs to another owner");
    const page = record(await this.transport.call("paranoid_getNativeHoldings", [address, cursor, limit], options));
    this.state(page);
    if (page.owner !== address || !Array.isArray(page.holdings)) throw new ProtocolError("Unexpected holdings owner or items");
    return page as unknown as NativeHoldingsPage;
  }

  async getCatalog(kind: NativeCatalogKind, cursor: NativeCatalogCursor | null = null, limit = 64, options?: CallOptions): Promise<NativeCatalogPage> {
    if (!["markets", "collections", "nft_listings"].includes(kind)) throw new ProtocolError("Unknown catalog kind");
    this.limit(limit, 64);
    if (cursor && cursor.kind !== kind) throw new ProtocolError("Catalog cursor belongs to another kind");
    const page = record(await this.transport.call("paranoid_getNativeCatalog", [kind, cursor, limit], options));
    this.state(page);
    if (page.kind !== kind || !Array.isArray(page.items)) throw new ProtocolError("Unexpected catalog kind or items");
    return page as unknown as NativeCatalogPage;
  }

  async getMarket(assetId: string, options?: CallOptions): Promise<NativeMarketDetails> {
    const details = record(await this.transport.call("paranoid_getNativeMarket", [digest(assetId)], options));
    this.state(details);
    if (!("item" in details)) throw new ProtocolError("Missing market item");
    return details as unknown as NativeMarketDetails;
  }

  async prepare(address: string, request: NativeRequest, expectedParentHash?: string, options?: CallOptions): Promise<NativeClientPlan> {
    owner(address);
    const normalized = canonicalNativeRequest(request);
    const parent = expectedParentHash === undefined ? null : digest(expectedParentHash);
    const protocol = await this.active(options);
    const plan = record(await this.transport.call("paranoid_prepareNativeIntent", [address, normalized, parent], options));
    if (plan.schema_version !== 1 || plan.owner_authorization_version !== OWNER_AUTHORIZATION_VERSION || plan.owner !== address) {
      throw new ProtocolError("Unsupported native plan schema, authorization version or owner");
    }
    for (const field of ["plan_id", "intent_id", "chain_id", "epoch_anchor"]) digest(plan[field]);
    if (this.expectedChainId !== undefined && plan.chain_id !== this.expectedChainId) throw new ProtocolError("Native plan belongs to another chain");
    if (height(plan.candidate_height) < protocol.activation_height!) throw new ProtocolError("Native plan precedes activation");
    if (typeof plan.parent_header_hex !== "string" || !/^[0-9a-f]{424}$/.test(plan.parent_header_hex)) throw new ProtocolError("Invalid canonical parent header");
    const review = record(plan.review);
    this.state({ height: plan.candidate_height, block_hash: review.parent_hash, state_root: review.state_root });
    if (parent !== null && review.parent_hash !== parent) throw new ProtocolError("Native plan changed the expected parent");
    if (JSON.stringify(canonicalNativeRequest(review.request as NativeRequest)) !== JSON.stringify(normalized)) throw new ProtocolError("Native plan changed the approved request");
    for (const field of ["fee_micronoid", "noid_debit_micronoid", "noid_credit_micronoid"]) amount(review[field]);
    for (const field of ["fee_limit_micronoid", "reserve_deposit_micronoid", "initial_buy_cost_micronoid", "redemption_micronoid", "quoted_output", "minimum_output", "serial", "last_serial"]) {
      if (review[field] != null) amount(review[field]);
    }
    if (review.valid_until != null) height(review.valid_until);
    height(review.input_count); height(review.output_count);
    const kind = normalized.action === "trade" ? "trade" : "operation";
    const magic = kind === "trade" ? "4e4f4944544f3231" : "4e4f49444e543231";
    if (plan.intent_kind !== kind || typeof plan.unsigned_intent_hex !== "string" || !/^(?:[0-9a-f]{2})+$/.test(plan.unsigned_intent_hex)
      || !plan.unsigned_intent_hex.startsWith(magic)) throw new ProtocolError("Unexpected native intent encoding");
    return plan as unknown as NativeClientPlan;
  }

  async submitAuthorizedIntent(intentHex: string, options?: CallOptions): Promise<string> {
    if (typeof intentHex !== "string" || intentHex.length > 8 * 1024 * 1024 || !/^(?:[0-9a-f]{2})+$/.test(intentHex)
      || !(intentHex.startsWith("4e4f49444e543231") || intentHex.startsWith("4e4f4944544f3231"))) throw new ProtocolError("Invalid native intent bytes");
    await this.active(options);
    return digest(await this.transport.call("paranoid_submitTxIntent", [intentHex], options));
  }

  private limit(limit: number, maximum = 256): void {
    if (!Number.isInteger(limit) || limit < 1 || limit > maximum) throw new RangeError(`Page limit must be 1 through ${maximum}`);
  }
  private state(value: Record<string, unknown>): void {
    height(value.height); digest(value.block_hash); digest(value.state_root);
  }
}
