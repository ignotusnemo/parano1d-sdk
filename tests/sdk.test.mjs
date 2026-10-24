import test from "node:test";
import assert from "node:assert/strict";
import { ActivationPendingError, JsonRpcTransport, MAX_U64, NativeClient, ProtocolError,
  RpcError, StateChangedError, canonicalNativeRequest, formatUnits, integerString, parseUnits,
  parseNativeCatalogKey } from "../dist/index.js";

const hash = "ab".repeat(32);
const address = "o1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";
const request = { action: "create_token", whole_tokens: "100000", metadata_hash: hash };
const protocol = {
  tip_height: 19, activation_height: 20, active_at_next_block: true,
  runtime_available: true, initial_creator_purchase: true, nft_batch_limit: 124,
  token_decimals: 6, minimum_launch_whole_tokens: "100000", maximum_launch_whole_tokens: "1000000000",
  minimum_backing_micronoid_per_whole_token: "1000", pages: 63, headers: 63,
  actions: 128, markets: 4, trade_policies: 48, trade_funding_inputs: 64,
};

function plan(input = request) {
  const normalized = canonicalNativeRequest(input);
  const trade = input.action === "trade";
  return {
    schema_version: 1, plan_id: hash, intent_id: hash, owner: address, candidate_height: 20,
    parent_header_hex: "00".repeat(212), chain_id: hash, epoch_anchor: hash,
    owner_authorization_version: 4, intent_kind: trade ? "trade" : "operation",
    unsigned_intent_hex: (trade ? "4e4f4944544f3231" : "4e4f49444e543231") + "00",
    review: {
      parent_hash: hash, state_root: hash, request: normalized, fee_micronoid: "1000",
      fee_limit_micronoid: null, noid_debit_micronoid: "100001000", noid_credit_micronoid: "0",
      reserve_deposit_micronoid: "100000000", initial_buy_cost_micronoid: null,
      redemption_micronoid: null, quoted_output: null, minimum_output: null,
      valid_until: null, asset_id: hash, collection_id: null, serial: null, last_serial: null,
      input_count: 1, output_count: 2, pending_quote: null,
    },
  };
}

function client(change = {}) {
  const calls = [];
  const transport = {
    async call(method, params) {
      calls.push({ method, params });
      if (method === "paranoid_getNativeProtocol") return { ...protocol, ...change.protocol };
      if (method === "paranoid_prepareNativeIntent") {
        const result = plan(params[1]);
        change.plan?.(result);
        return result;
      }
      if (method === "paranoid_submitTxIntent") return hash;
      throw new Error(`Unexpected call ${method}`);
    },
  };
  return { sdk: new NativeClient(transport, { expectedChainId: hash }), calls };
}

test("exact amounts round-trip at u64 and decimal precision boundaries", () => {
  for (const n of [0n, 1n, 999_999n, 1_000_000n, 9_007_199_254_740_993n, MAX_U64]) {
    assert.equal(parseUnits(formatUnits(n)), n.toString());
  }
  assert.equal(parseUnits("1.25"), "1250000");
  assert.equal(parseUnits("0001.000001"), "1000001");
  assert.equal(integerString("000123"), "123");
});

test("amounts reject rounding, scientific notation, signs, unsafe numbers and overflow", () => {
  for (const n of ["0.0000001", "1e6", "-1", "+1", "1,25", "", " 1", "1.", "18446744073709.551616"]) {
    assert.throws(() => parseUnits(n));
  }
  assert.throws(() => integerString(1));
  assert.throws(() => integerString(MAX_U64 + 1n));
});

test("request normalization matches Rust optional fields and declaration order", () => {
  const trade = canonicalNativeRequest({ action: "trade", asset_id: hash.toUpperCase(), buy: true, gross_input: "0001" });
  assert.deepEqual(trade, { action: "trade", asset_id: hash, buy: true, gross_input: "1", minimum_output: null, slippage_bps: null, valid_until: null });
  assert.deepEqual(canonicalNativeRequest({ ...request, initial_buy_units: null }), request);
});

test("unknown request fields reject before reaching the transport", async () => {
  const { sdk, calls } = client();
  await assert.rejects(sdk.prepare(address, { ...request, secret: "unexpected" }), /Unknown native request field/);
  assert.equal(calls.length, 0);
});

test("invalid amounts, identities, NFT batches and heights reject locally", () => {
  for (const input of [
    { ...request, whole_tokens: "0" },
    { ...request, metadata_hash: "ab" },
    { action: "mint_nfts", collection_id: hash, metadata_hashes: [] },
    { action: "trade", asset_id: hash, buy: true, gross_input: "1", slippage_bps: 10001 },
    { action: "list_nft", collection_id: hash, serial: "1", ask_micronoid: "1", expiry_height: 2 ** 53 },
  ]) assert.throws(() => canonicalNativeRequest(input));
});

test("preparation stays disabled until the activation block is the candidate", async () => {
  const { sdk, calls } = client({ protocol: { tip_height: 18, active_at_next_block: false } });
  await assert.rejects(sdk.prepare(address, request), ActivationPendingError);
  assert.deepEqual(calls.map(c => c.method), ["paranoid_getNativeProtocol"]);
});

test("preparation supports the first activated candidate block", async () => {
  const { sdk, calls } = client();
  const result = await sdk.prepare(address, request, hash);
  assert.equal(result.candidate_height, 20);
  assert.equal(result.owner_authorization_version, 4);
  assert.deepEqual(calls[1].params, [address, request, hash]);
});

test("an unavailable native runtime prevents planning", async () => {
  const { sdk, calls } = client({ protocol: { runtime_available: false } });
  await assert.rejects(sdk.prepare(address, request), /runtime is unavailable/);
  assert.equal(calls.length, 1);
});

test("inconsistent activation reports reject", async () => {
  const { sdk } = client({ protocol: { tip_height: 1 } });
  await assert.rejects(sdk.prepare(address, request), /activation context/);
});

test("catalog queries use the RPC ceiling of 64 items and holdings allow 256", async () => {
  const calls = [];
  const sdk = new NativeClient({ async call(method, params) {
    calls.push({ method, params });
    const state = { height: 20, block_hash: hash, state_root: hash, next: null };
    if (method === "paranoid_getNativeCatalog") return { ...state, kind: params[0], scanned: 0, items: [] };
    return { ...state, owner: params[0], key_index: null, holdings: [] };
  } });
  await sdk.getCatalog("markets");
  assert.equal(calls[0].params[2], 64);
  await assert.rejects(sdk.getCatalog("markets", null, 65), RangeError);
  await sdk.getHoldings(address, null, 256);
  assert.equal(calls[1].params[2], 256);
});

test("catalog keys decode market and collection identities and exact u64 NFT serials", () => {
  assert.deepEqual(parseNativeCatalogKey("markets", "8000" + hash), { kind: "markets", asset_id: hash });
  assert.deepEqual(parseNativeCatalogKey("collections", "0004" + hash), { kind: "collections", collection_id: hash });
  assert.deepEqual(parseNativeCatalogKey("nft_listings", "8001" + hash + "ffffffffffffffff"), {
    kind: "nft_listings", collection_id: hash, serial: MAX_U64.toString(),
  });
  for (const [kind, key] of [
    ["markets", hash], ["markets", "0004" + hash], ["nft_listings", "8001" + hash + "0000000000000000"],
    ["nft_listings", "8001" + hash + "0001"], ["collections", "0004" + "zz".repeat(32)],
  ]) assert.throws(() => parseNativeCatalogKey(kind, key), ProtocolError);
});

for (const [name, change] of [
  ["owner", p => p.owner = "o1anotherowner"],
  ["authorization version", p => p.owner_authorization_version = 3],
  ["chain", p => p.chain_id = "cd".repeat(32)],
  ["parent", p => p.review.parent_hash = "cd".repeat(32)],
  ["request", p => p.review.request.whole_tokens = "200000"],
  ["candidate", p => p.candidate_height = 19],
  ["schema", p => p.schema_version = 2],
  ["intent kind", p => p.intent_kind = "trade"],
]) {
  test(`plan envelope rejects a changed ${name}`, async () => {
    const { sdk } = client({ plan: change });
    await assert.rejects(sdk.prepare(address, request, hash), ProtocolError);
  });
}

test("trade plans retain exact explicit slippage and use the trade wire kind", async () => {
  const { sdk } = client();
  const trade = { action: "trade", asset_id: hash, buy: true, gross_input: parseUnits("1"), slippage_bps: 1000 };
  const result = await sdk.prepare(address, trade);
  assert.equal(result.intent_kind, "trade");
  assert.equal(result.review.request.slippage_bps, 1000);
});

test("submission requires activation and relays only the supplied native bytes", async () => {
  const { sdk, calls } = client();
  const bytes = "4e4f49444e543231" + "11".repeat(32);
  assert.equal(await sdk.submitAuthorizedIntent(bytes), hash);
  assert.deepEqual(calls[1], { method: "paranoid_submitTxIntent", params: [bytes] });
  await assert.rejects(client({ protocol: { active_at_next_block: false } }).sdk.submitAuthorizedIntent(bytes), ActivationPendingError);
});

test("transport preserves exact JSON integers and request identities", async () => {
  const rpc = new JsonRpcTransport("http://127.0.0.1:9601", { fetch: async (_url, init) => {
    const input = JSON.parse(init.body);
    assert.equal(input.params[0], MAX_U64.toString());
    assert.equal(init.credentials, "omit");
    assert.equal(init.redirect, "error");
    return Response.json({ jsonrpc: "2.0", id: input.id, result: MAX_U64.toString() });
  } });
  assert.equal(await rpc.call("paranoid_example", [MAX_U64.toString()]), MAX_U64.toString());
});

test("transport invokes Fetch with the browser global receiver", async () => {
  const rpc = new JsonRpcTransport("http://localhost:9601", { fetch: async function (_url, init) {
    assert.equal(this, globalThis);
    const { id } = JSON.parse(init.body);
    return Response.json({ jsonrpc: "2.0", id, result: true });
  } });
  assert.equal(await rpc.call("paranoid_example", []), true);
});

test("transport distinguishes State changes and performs no automatic retry", async () => {
  let calls = 0;
  const rpc = new JsonRpcTransport("http://localhost:9601", { fetch: async (_url, init) => {
    calls++;
    const { id } = JSON.parse(init.body);
    return Response.json({ jsonrpc: "2.0", id, error: { code: -32041, message: "State changed", data: { height: 21, block_hash: hash } } });
  } });
  await assert.rejects(rpc.call("paranoid_prepareNativeIntent", []), error => error instanceof StateChangedError && error instanceof RpcError && error.data.height === 21);
  assert.equal(calls, 1);
});

test("transport rejects mismatched, ambiguous and malformed envelopes", async () => {
  for (const body of [
    { jsonrpc: "2.0", id: "wrong", result: null },
    { jsonrpc: "2.0", id: "1", result: null, error: {} },
    { jsonrpc: "2.0", id: "1" },
    [],
  ]) {
    const rpc = new JsonRpcTransport("http://localhost:9601", { fetch: async () => Response.json(body) });
    await assert.rejects(rpc.call("paranoid_example", []), ProtocolError);
  }
});

test("transport bounds streamed response bytes", async () => {
  const rpc = new JsonRpcTransport("http://localhost:9601", { maxResponseBytes: 16,
    fetch: async () => new Response("x".repeat(17)) });
  await assert.rejects(rpc.call("paranoid_example", []), /byte limit/);
});

test("transport propagates cancellation", async () => {
  const signal = new AbortController();
  const rpc = new JsonRpcTransport("http://localhost:9601", { fetch: async (_url, init) => {
    init.signal.throwIfAborted();
    return new Promise((_resolve, reject) => init.signal.addEventListener("abort", () => reject(init.signal.reason), { once: true }));
  } });
  const pending = rpc.call("paranoid_example", [], { signal: signal.signal });
  signal.abort(new Error("User cancelled"));
  await assert.rejects(pending, /User cancelled/);
});

test("transport accepts HTTPS and loopback HTTP and rejects credentials in URLs", () => {
  new JsonRpcTransport("https://wallet.example.org/rpc");
  new JsonRpcTransport("http://[::1]:9601");
  assert.throws(() => new JsonRpcTransport("http://wallet.example.org/rpc"));
  assert.throws(() => new JsonRpcTransport("https://user:secret@wallet.example.org/rpc"));
});
