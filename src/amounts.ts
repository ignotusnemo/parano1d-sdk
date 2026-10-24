export const DECIMALS = 6;
export const UNITS_PER_NOID = 1_000_000n;
export const MAX_U64 = 18_446_744_073_709_551_615n;

export function integerString(value: string | bigint): string {
  if (typeof value !== "string" && typeof value !== "bigint") {
    throw new TypeError("Amounts require a decimal string or bigint");
  }
  const text = value.toString();
  if (!/^[0-9]+$/.test(text) || text.length > 32) {
    throw new RangeError("Amount must be an unsigned decimal integer");
  }
  const amount = BigInt(text);
  if (amount > MAX_U64) throw new RangeError("Amount exceeds u64");
  return amount.toString();
}

export function parseUnits(value: string): string {
  if (typeof value !== "string" || value.length > 32 || !/^[0-9]+(?:\.[0-9]{1,6})?$/.test(value)) {
    throw new RangeError("Use a decimal amount with at most six decimal places");
  }
  const [whole = "0", fraction = ""] = value.split(".");
  return integerString(BigInt(whole) * UNITS_PER_NOID + BigInt(fraction.padEnd(DECIMALS, "0")));
}

export function formatUnits(value: string | bigint): string {
  const amount = BigInt(integerString(value));
  const whole = amount / UNITS_PER_NOID;
  const fraction = (amount % UNITS_PER_NOID).toString().padStart(DECIMALS, "0").replace(/0+$/, "");
  return fraction ? `${whole}.${fraction}` : whole.toString();
}
