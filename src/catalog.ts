import { ProtocolError } from "./rpc.js";
import type { NativeCatalogKind } from "./types.js";

export type NativeCatalogIdentity =
  | { kind: "markets"; asset_id: string }
  | { kind: "collections"; collection_id: string }
  | { kind: "nft_listings"; collection_id: string; serial: string };

export function parseNativeCatalogKey(kind: NativeCatalogKind, key: string): NativeCatalogIdentity {
  const shape = {
    markets: { prefix: "8000", length: 68 },
    collections: { prefix: "0004", length: 68 },
    nft_listings: { prefix: "8001", length: 84 },
  }[kind];
  if (!shape || typeof key !== "string" || !/^[0-9a-f]+$/i.test(key)
    || key.length !== shape.length || key.slice(0, 4).toLowerCase() !== shape.prefix) {
    throw new ProtocolError("Invalid native catalog key for its kind");
  }
  const id = key.slice(4, 68).toLowerCase();
  if (kind === "markets") return { kind, asset_id: id };
  if (kind === "collections") return { kind, collection_id: id };
  const serial = BigInt(`0x${key.slice(68)}`).toString();
  if (serial === "0") throw new ProtocolError("NFT serial must be positive");
  return { kind, collection_id: id, serial };
}
