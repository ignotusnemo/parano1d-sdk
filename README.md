# Parano1d SDK

Typed client integration for native Parano1d tokens, launchpad trading, DEX markets and NFTs. The client reads State-bound catalogs and holdings, prepares operations for an explicit owner address and submits completed native intents. Exact decimal strings preserve every base unit.

The protocol target is Parano1d v2.1.0. `protocol.json` pins the released source and RPC definitions. Mainnet activation is block **279370**. Local networks use their node-reported activation height.

## Development

```sh
npm ci
npm test
```

The package builds ESM JavaScript and TypeScript declarations. Runtime code uses platform Fetch, AbortController, Web Streams and BigInt.

## Read and prepare

Run direct node integration on the service host. Keep node RPC on loopback. The wallet application serves its browser API and interface over the same HTTPS origin.

```ts
import { JsonRpcTransport, NativeClient, parseUnits } from "@parano1d/sdk";

const client = new NativeClient(new JsonRpcTransport("http://127.0.0.1:9601"));
const protocol = await client.getProtocol();
const markets = await client.getCatalog("markets");
const holdings = await client.getHoldings(ownerAddress);

const plan = await client.prepare(ownerAddress, {
  action: "trade",
  asset_id: assetId,
  buy: true,
  gross_input: parseUnits("1"),
  slippage_bps: 1000,
}, reviewedParentHash);
```

Catalog items carry typed index keys. Use `parseNativeCatalogKey("markets", item.key).asset_id` to obtain a market's asset ID. NFT listing keys contain the collection ID and an exact decimal serial. Follow each page's State-bound cursor to continue discovery.

Preparation checks activation for the candidate block, runtime availability, schema, owner, authorization version, operation kind, request identity and expected parent. Pass `expectedChainId` when constructing a client to bind the returned chain identity. Review the canonical parent header, wire intent, exact funding, recipients, fees and operation terms before authorizing.

The browser authorization layer must decode the canonical intent, recompute its statement and plan identity, and verify its completed Owner capsule. `submitAuthorizedIntent` relays the resulting canonical bytes to the node. A State change returns `StateChangedError` with the node's current context, allowing the application to obtain a fresh plan and approval.

## Supported requests

- Fixed-supply token creation, optional creator purchase, transfer and burn/redemption.
- Bonding-curve and DEX trades with explicit minimum output or slippage and expiry.
- Collection creation, individual and batch minting, NFT transfer and burn.
- NFT listing, purchase and cancellation.

Amounts are base-unit decimal strings. Both NOID and fungible tokens use six decimal places. `parseUnits("1.25")` returns `"1250000"`. `formatUnits("1250000")` returns `"1.25"`. Heights and page counts use exact safe integers. The transport bounds response sizes, checks JSON-RPC request identities and supports cancellation and timeouts.


## Rust authorization

The `parano1d-authorization` crate provides the same portable checks used by the browser wallet. `WalletOperation` accepts ordinary payments, ABI 3 contract operations and `NativeOperationPlan` values.

```rust,ignore
use parano1d_authorization::{prepare, WalletOperation};

let review = operation.review()?;
let (request, pending) = prepare(&spend_secret)?.begin(operation)?;
let response = proving_service(request).await?;
let authorized_intent = pending.finish(&response)?;
```

`NativeOperationPlan` takes the original request, expected chain and parent, and approved fee cap. It decodes the canonical wire format, recomputes the plan identity, checks native operation terms and derives the Owner statement. `Pending::finish` consumes its state and verifies the full capsule before returning an authorized intent.

The `Operation` API supports ABI 3 contract openings, controller selection, call height and native policy preflight. Applications can compose it with existing contract templates and Pruv output.

The source under `vendor/` is pinned to the released commit in `vendor/upstream.json`. Staged proving adapters and the WebAssembly arithmetic backend are SDK additions.

Apache-2.0.
