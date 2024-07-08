//! Signature shares aggregation
//!
//! In this phase, Coordinator aggregates signature shares into a regular signature.
//!
//! For more details, refer to [parent module](super) docs, or [Section 5.3] of the draft.
//!
//! [Section 5.3]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html#name-signature-share-aggregation

use alloc::vec::Vec;
use core::fmt;

use generic_ec::{NonZero, Point, Scalar};

use crate::{ciphersuite::NormalizedPoint, Ciphersuite, SignerIndex};

use super::{round1::PublicCommitments, round2::SigShare, utils};

#[derive(Debug, Clone, Copy)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound = "")
)]
/// Schnorr Signature
pub struct Signature<C: Ciphersuite + ?Sized> {
    /// $R$ component of the signature
    pub r: crate::ciphersuite::NormalizedPoint<C, Point<C::Curve>>,
    /// $z$ component of the signature
    pub z: Scalar<C::Curve>,
}

impl<C: Ciphersuite> Signature<C> {
    /// Verifies signature against a public key and a message
    pub fn verify(
        &self,
        public_key: &NormalizedPoint<C, NonZero<Point<C::Curve>>>,
        msg: &[u8],
    ) -> Result<(), InvalidSignature> {
        let challenge = C::compute_challenge(&self.r, public_key, msg);

        let lhs = Point::generator() * self.z;
        let rhs = *self.r + **public_key * challenge;

        if lhs == rhs {
            Ok(())
        } else {
            Err(InvalidSignature)
        }
    }

    /// Size of signature in bytes serialized via [`Signature::write_to_slice`]
    pub fn serialized_len() -> usize {
        C::NORMALIZED_POINT_SIZE + C::SCALAR_SIZE
    }

    /// Writes serialized signature to the bytes buffer
    ///
    /// Bytes buffer size must be at least [`Signature::serialized_len()`], otherwise
    /// content of output buffer is unspecified
    pub fn write_to_slice(&self, out: &mut [u8]) {
        let Some(point_out) = out.get_mut(..C::NORMALIZED_POINT_SIZE) else {
            return;
        };
        point_out.copy_from_slice(C::serialize_normalized_point(&self.r).as_ref());

        let Some(scalar_out) =
            out.get_mut(C::NORMALIZED_POINT_SIZE..C::NORMALIZED_POINT_SIZE + C::SCALAR_SIZE)
        else {
            return;
        };
        scalar_out.copy_from_slice(C::serialize_scalar(&self.z).as_ref());
    }

    /// Parses signature from the bytes buffer
    ///
    /// Signature is expected to be serialized via [`Signature::write_to_slice()`]. If signature is invalid,
    /// returns `None`.
    pub fn read_from_slice(bytes: &[u8]) -> Option<Self> {
        let r = bytes.get(..C::NORMALIZED_POINT_SIZE)?;
        let z = bytes.get(C::NORMALIZED_POINT_SIZE..C::NORMALIZED_POINT_SIZE + C::SCALAR_SIZE)?;

        let r = C::deserialize_normalized_point(r).ok()?;
        let z = C::deserialize_scalar(z).ok()?;

        Some(Self { r, z })
    }
}

/// Aggregate [signature shares](SigShare) into a regular [Schnorr signature](Signature)
///
/// Inputs:
/// * Public `key_info`
/// * List of signers, their commitments and signature shares
/// * `msg` being signed
///
/// Outputs [Schnorr signature](Signature)
pub fn aggregate<C: Ciphersuite>(
    key_info: &crate::key_share::KeyInfo<C::Curve>,
    signers: &[(SignerIndex, PublicCommitments<C::Curve>, SigShare<C::Curve>)],
    msg: &[u8],
) -> Result<Signature<C>, AggregateError> {
    // --- Retrieve and Validate Data
    let mut comm_list = signers
        .iter()
        .map(|(j, comm, _sig_share)| {
            key_info
                .share_preimage(*j)
                .map(|id| (id, *comm))
                .ok_or(Reason::UnknownSigner(*j))
        })
        .collect::<Result<Vec<_>, _>>()?;
    comm_list.sort_unstable_by_key(|(i, _)| *i);

    // Check that no signer appears in the list more than once
    if comm_list
        .iter()
        .skip(1)
        .zip(&comm_list)
        .any(|(current, prev)| current.0 == prev.0)
    {
        return Err(Reason::SameSignerTwice.into());
    }

    // --- The Aggregation
    let binding_factor_list =
        utils::compute_binding_factors::<C>(key_info.shared_public_key, &comm_list, msg);
    let group_commitment = utils::compute_group_commitment::<C>(&comm_list, &binding_factor_list);
    let z = signers
        .iter()
        .map(|(_j, _comm, sig_share)| sig_share.0)
        .sum();

    let sig = Signature {
        r: C::normalize_point(group_commitment),
        z,
    };
    sig.verify(&C::normalize_point(key_info.shared_public_key), msg)
        .map_err(|_| Reason::InvalidSig)?;

    Ok(sig)
}

/// Aggregation error
#[derive(Debug)]
pub struct AggregateError(Reason);

#[derive(Debug)]
enum Reason {
    UnknownSigner(SignerIndex),
    SameSignerTwice,
    InvalidSig,
}

impl From<Reason> for AggregateError {
    fn from(err: Reason) -> Self {
        Self(err)
    }
}

impl fmt::Display for AggregateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Reason::UnknownSigner(j) => write!(f, "unknown signer {j}"),
            Reason::SameSignerTwice => {
                f.write_str("same signer appears more than once in the list")
            }
            Reason::InvalidSig => f.write_str("invalid signature"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AggregateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            Reason::UnknownSigner(_) | Reason::SameSignerTwice | Reason::InvalidSig => None,
        }
    }
}

/// Signature verification failed
#[derive(Debug)]
pub struct InvalidSignature;

impl fmt::Display for InvalidSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid signature")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidSignature {}
