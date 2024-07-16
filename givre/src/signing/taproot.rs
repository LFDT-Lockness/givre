//! Taproot tweak
//!
//! This module provides functionality for tweaking the public key
//! to obtain a tweaked child key from the parent key following the
//! [BIP-341](https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki)

use digest::Digest;
use generic_ec::{NonZero, Point, Scalar};

use crate::{ciphersuite::NormalizedPoint, Ciphersuite};

/// Calculates the tweak for given (normalized) public key and merkle root
pub fn tweak<C: Ciphersuite>(
    public_key: NormalizedPoint<C, NonZero<Point<C::Curve>>>,
    merkle_root: Option<[u8; 32]>,
) -> Option<Scalar<C::Curve>> {
    let tag = sha2::Sha256::digest("TapTweak");
    let hash = sha2::Sha256::new()
        .chain_update(tag)
        .chain_update(tag)
        .chain_update(public_key.to_bytes())
        .chain_update(if let Some(root) = &merkle_root {
            root.as_slice()
        } else {
            &[]
        })
        .finalize();
    Scalar::from_be_bytes(hash).ok()
}

/// Tweaks the public key and returns tweaked child public key
///
/// Returns `None` if tweak is not defined for given input (probability of
/// that is negligible).
pub fn tweak_public_key<C: Ciphersuite>(
    public_key: NormalizedPoint<C, NonZero<Point<C::Curve>>>,
    merkle_root: Option<[u8; 32]>,
) -> Option<NonZero<Point<C::Curve>>> {
    let t = tweak::<C>(public_key, merkle_root)?;
    NonZero::from_point(*public_key + Point::generator() * t)
}
