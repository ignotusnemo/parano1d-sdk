// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Paranoid Zero.

//! Carry-less multiplication using four interleaved integer lanes.
//! The low product keeps one parity bit per four-bit column. The largest
//! retained column has at most sixteen terms; its carry leaves the u64.
//! Reversal obtains coefficients 64..126 from a second low product.

#[inline(always)]
fn low_product(a: u64, b: u64) -> u64 {
    const MASKS: [u64; 4] = [
        0x1111111111111111,
        0x2222222222222222,
        0x4444444444444444,
        0x8888888888888888,
    ];
    let mut out = 0;
    for lane in 0..4 {
        let mut column = 0;
        for left in 0..4 {
            let right = (lane + 4 - left) & 3;
            column ^= (a & MASKS[left]).wrapping_mul(b & MASKS[right]);
        }
        out |= column & MASKS[lane];
    }
    out
}

#[inline(always)]
pub(super) fn multiply(a: u64, b: u64) -> u128 {
    let low = low_product(a, b);
    let high = low_product(a.reverse_bits(), b.reverse_bits()).reverse_bits() >> 1;
    (low as u128) | ((high as u128) << 64)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn reference(a: u64, b: u64) -> u128 {
        let mut out = 0u128;
        for bit in 0..64 {
            out ^= ((a as u128) << bit) & 0u128.wrapping_sub(((b >> bit) & 1) as u128);
        }
        out
    }
    #[test]
    fn every_basis_pair_matches_polynomial_multiplication() {
        for left in 0..64 {
            for right in 0..64 {
                assert_eq!(
                    multiply(1u64 << left, 1u64 << right),
                    1u128 << (left + right)
                );
            }
        }
    }
    #[test]
    fn dense_and_random_products_match_the_bitwise_reference() {
        let mut state = 0x8317b7da4c50ef21u64;
        for a in [0, 1, u64::MAX, 0xaaaaaaaaaaaaaaaa, 0x5555555555555555] {
            for b in [0, 1, u64::MAX, 0xaaaaaaaaaaaaaaaa, 0x5555555555555555] {
                assert_eq!(multiply(a, b), reference(a, b));
            }
        }
        for _ in 0..100000 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let a = state;
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let b = state;
            assert_eq!(multiply(a, b), reference(a, b));
        }
    }
}
