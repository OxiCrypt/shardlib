//! This module implements Shamir's Secret Sharing.
mod make_shares;
mod recover_file;
use crypto_bigint::{NonZero, U512};
pub use make_shares::shamir_split;
pub use recover_file::reconstruct_secret_mod;
use std::num;
use zeroize::{Zeroize, Zeroizing};
#[derive(Debug)]
pub enum ShamirError {
    TooFewShares(u8), // Signifies too few shares to compute polynomial
    ModError,         // Signifies error where modulus is zero
    DuplicateShares,  // Signifies error where two identical
    KeyExtraction,    // Signifies error in extracting key from U512
}
#[derive(Zeroize)]
pub struct Coeffs(Vec<U512>);
impl Drop for Coeffs {
    fn drop(&mut self) {
        self.zeroize();
    }
}
#[derive(Zeroize)]
pub struct Shares(Vec<(u8, U512)>);
impl Drop for Shares {
    fn drop(&mut self) {
        self.zeroize();
    }
}
impl Shares {
    #[must_use]
    pub fn as_vec(&self) -> Zeroizing<Vec<[u8; 65]>> {
        let mut vec: Zeroizing<Vec<[u8; 65]>> = Zeroizing::new(Vec::with_capacity(self.0.len()));
        for i in &self.0 {
            let mut temparray: Zeroizing<[u8; 65]> = Zeroizing::new([0u8; 65]);
            temparray.as_mut()[1..65].copy_from_slice(i.1.to_be_bytes().as_slice());
            temparray[0] = i.0;
            vec.push(*temparray);
        }
        vec
    }
    #[must_use]
    pub fn from_slice(slice: &[[u8; 65]]) -> Self {
        let mut return_val = Self(Vec::with_capacity(slice.len()));
        for rawshare in slice {
            return_val
                .0
                .push((rawshare[0], U512::from_be_slice(&rawshare[1..65])));
        }
        return_val
    }
    pub fn from_key_slice(
        threshold: num::NonZero<u8>,
        shares_out: num::NonZero<u8>,
        key: &Zeroizing<[u8; 32]>,
    ) -> Result<Shares, crate::Error> {
        shamir_split(threshold, shares_out, key)
    }
}
// Helper Functions
// This is a helper function because I could not find a way to get const working
fn make_prime() -> U512 {
    // What you will read is the smallest prime above 2^256.
    // I will not be using Mersenne primes because they will be much bigger and slower
    U512::from_be_hex(
        "00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000129",
    )
    // This will always produce a valid biguint
}
// Nonzeroers
fn uint_to_nz_uint(n: &U512) -> Result<NonZero<U512>, ShamirError> {
    n.to_nz().ok_or(ShamirError::ModError)
}
