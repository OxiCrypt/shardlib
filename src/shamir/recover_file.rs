use super::ShamirError;
use super::{Shares, make_prime, uint_to_nz_uint};
use crypto_bigint::U512;
use std::num::NonZero;
use std::ops::ShrAssign;
use zeroize::Zeroizing;

/// Finds the modular inverse of `a` given that `prime` is the modulus.
/// Uses Fermat's little theorem: a^(p-2) mod p = a^(-1) mod p.
fn mod_inverse(prime: &U512, a: &U512) -> Result<Zeroizing<U512>, ShamirError> {
    let mut exp: U512 = *prime - U512::from_u8(2);
    let prime_nz = uint_to_nz_uint(prime)?;
    let mut result = Zeroizing::new(U512::ONE);
    let mut base = a % prime_nz;

    while exp.is_nonzero().to_bool() {
        if exp.is_odd().to_bool() {
            *result = result.mul_mod(&base, &prime_nz);
        }
        base = base.mul_mod(&base, &prime_nz);
        exp.shr_assign(1);
    }

    Ok(result)
}

/// Reconstructs the secret from shares on the polynomial using Lagrange interpolation.
///
/// `shares` is a slice of (x, y) pairs where x is the share index (1-based) and
/// y is the share value. `p` is the prime modulus. `req` is the minimum threshold.
pub fn reconstruct_secret_mod(
    shares: &Shares,
    req: NonZero<u8>,
) -> Result<Zeroizing<[u8; 32]>, crate::Error> {
    if shares.as_vec().len() < req.get() as usize {
        Err(ShamirError::TooFewShares(req.get()))?;
    }

    let shares = &shares.as_vec()[..req.get() as usize];
    let n = shares.len();

    for i in 0..n {
        for j in (i + 1)..n {
            if shares[i][0] == shares[j][0] {
                Err(ShamirError::DuplicateShares)?;
            }
        }
    }

    let p = make_prime();
    let p_nz = uint_to_nz_uint(&p)?;

    let mut secret = U512::ZERO;

    for i in 0..n {
        let xi = shares[i][0];

        let yi = Zeroizing::new(U512::from_be_slice(&shares[i][1..65]));
        let xi = U512::from_u8(xi);

        let mut term = *yi % p;

        for (j, share) in shares.iter().enumerate() {
            if i != j {
                let xj = share[0];
                let xj = U512::from_u8(xj);

                // numerator = (0 - xj) mod p
                let numerator = p - xj;

                // denominator = (xi - xj) mod p (safe wrap)
                let denominator = if xi >= xj { xi - xj } else { p - (xj - xi) };

                let inv = mod_inverse(&p, &denominator)?;

                term = term.mul_mod(&numerator, &p_nz);
                term = term.mul_mod(&inv, &p_nz);
            }
        }

        secret = secret.add_mod(&term, &p_nz);
    }

    Ok(Zeroizing::new(
        secret.to_be_bytes().as_slice()[32..]
            .try_into()
            .map_err(|_| ShamirError::KeyExtraction)?,
    ))
}
