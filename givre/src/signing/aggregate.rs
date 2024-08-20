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

/// Aggregation options
///
/// Like [`aggregate`] but allows to specify additional options like the HD derivation path
pub struct AggregateOptions<'a, C: Ciphersuite> {
    key_info: &'a crate::key_share::KeyInfo<C::Curve>,
    signers: &'a [(SignerIndex, PublicCommitments<C::Curve>, SigShare<C::Curve>)],
    msg: &'a [u8],

    /// Additive shift derived from HD path
    hd_additive_shift: Option<Scalar<C::Curve>>,
    /// Possible values:
    /// * `None` if it wasn't specified
    /// * `Some(None)` if script tree is empty
    /// * `Some(Some(root))` if script tree is not empty
    ///
    /// It must be `None` when `C::IS_TAPROOT` is `true`, and it must be `Some(_)` otherwise
    taproot_merkle_root: Option<Option<[u8; 32]>>,
}

impl<'a, C: Ciphersuite> AggregateOptions<'a, C> {
    /// Constructs aggregate options
    ///
    /// Inputs:
    /// * Public `key_info`
    /// * List of signers, their commitments and signature shares
    /// * `msg` being signed
    pub fn new(
        key_info: &'a crate::key_share::KeyInfo<C::Curve>,
        signers: &'a [(SignerIndex, PublicCommitments<C::Curve>, SigShare<C::Curve>)],
        msg: &'a [u8],
    ) -> Self {
        Self {
            key_info,
            signers,
            msg,

            hd_additive_shift: None,
            taproot_merkle_root: None,
        }
    }

    /// Specifies HD derivation path
    ///
    /// If called twice, the second call overwrites the first.
    ///
    /// Returns error if the key doesn't support HD derivation, or if the path is invalid
    #[cfg(feature = "hd-wallets")]
    pub fn set_derivation_path<Index>(
        self,
        path: impl IntoIterator<Item = Index>,
    ) -> Result<Self, crate::key_share::HdError<<slip_10::NonHardenedIndex as TryFrom<Index>>::Error>>
    where
        slip_10::NonHardenedIndex: TryFrom<Index>,
    {
        use crate::key_share::HdError;

        let public_key = self
            .key_info
            .extended_public_key()
            .ok_or(HdError::DisabledHd)?;
        let additive_shift =
            utils::derive_additive_shift(public_key, path).map_err(HdError::InvalidPath)?;

        Ok(self.dangerous_set_hd_additive_shift(additive_shift))
    }

    /// Specifies HD derivation additive shift
    ///
    /// CAUTION: additive shift MUST BE derived from the extended public key obtained from
    /// the key share which is used for signing by calling [`utils::derive_additive_shift`].
    pub(crate) fn dangerous_set_hd_additive_shift(
        mut self,
        hd_additive_shift: Scalar<C::Curve>,
    ) -> Self {
        self.hd_additive_shift = Some(hd_additive_shift);
        self
    }

    /// Tweaks the key with specified merkle root following [BIP-341]
    ///
    /// Note that the taproot spec requires that any key must be tweaked. By default, if this
    /// method is not called for taproot-enabled ciphersuite, then an empty merkle root
    /// is assumed.
    ///
    /// The method returns an error if the ciphersuite doesn't support taproot, i.e. if
    /// [`Ciphersuite::IS_TAPROOT`] is `false`
    ///
    /// [BIP-341]: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
    #[cfg(feature = "taproot")]
    pub fn set_taproot_tweak(
        mut self,
        merkle_root: Option<[u8; 32]>,
    ) -> Result<Self, AggregateError> {
        if !C::IS_TAPROOT {
            return Err(Reason::NonTaprootCiphersuite.into());
        }

        self.taproot_merkle_root = Some(merkle_root);
        Ok(self)
    }

    /// Aggregate [signature shares](SigShare) into a regular [Schnorr signature](Signature)
    ///
    /// Outputs [Schnorr signature](Signature)
    pub fn aggregate(self) -> Result<Signature<C>, AggregateError> {
        aggregate_inner::<C>(
            self.key_info,
            self.hd_additive_shift,
            self.taproot_merkle_root,
            self.signers,
            self.msg,
        )
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
///
/// If you need to specify additional parameters such as HD derivation path or taproot merkle root,
/// use [`AggregateOptions`] instead.
pub fn aggregate<C: Ciphersuite>(
    key_info: &crate::key_share::KeyInfo<C::Curve>,
    signers: &[(SignerIndex, PublicCommitments<C::Curve>, SigShare<C::Curve>)],
    msg: &[u8],
) -> Result<Signature<C>, AggregateError> {
    AggregateOptions::new(key_info, signers, msg).aggregate()
}

/// Aggregate [signature shares](SigShare) into a regular [Schnorr signature](Signature)
///
/// Inputs:
/// * Public `key_info`
/// * `hd_additive_nonce` derived from HD derivation path
/// * `taproot_merkle_tree` for taproot tweak (which only takes effect if `C::IS_TAPROOT` is `true`)
/// * List of signers, their commitments and signature shares
/// * `msg` being signed
///
/// Outputs [Schnorr signature](Signature)
fn aggregate_inner<C: Ciphersuite>(
    key_info: &crate::key_share::KeyInfo<C::Curve>,
    hd_additive_shift: Option<Scalar<C::Curve>>,
    #[rustfmt::skip]
    #[cfg_attr(not(feature = "taproot"), allow(unused_variables))]
    taproot_merkle_root: Option<Option<[u8; 32]>>,
    signers: &[(SignerIndex, PublicCommitments<C::Curve>, SigShare<C::Curve>)],
    msg: &[u8],
) -> Result<Signature<C>, AggregateError> {
    // --- Retrieve and Validate Data
    let crate::key_share::DirtyKeyInfo {
        shared_public_key: pk,
        vss_setup,
        ..
    } = &**key_info;
    // Make sure we never use (potentially non-normalized) `key_info` anywhere
    // below by shadowing the variable.
    #[allow(unused_variables)]
    let key_info = ();

    // Derive HD child
    let pk = if let Some(additive_shift) = hd_additive_shift {
        let pk = pk + Point::generator() * additive_shift;
        NonZero::from_point(pk).ok_or(Reason::HdChildPkZero)?
    } else {
        *pk
    };

    // Taproot: Normalize the public key. Note that for non-taproot ciphersuites we still
    // need PK to be normalized as functions below accept normalized PK. However, for
    // non-taproot ciphersuites, normalization is an identity function
    let pk = C::normalize_point(pk);

    #[cfg(feature = "taproot")]
    let pk = if C::IS_TAPROOT {
        // Taproot: tweak the key share
        let merkle_root = taproot_merkle_root.ok_or(Reason::MissingTaprootMerkleRoot)?;
        let t = crate::signing::taproot::tweak::<C>(pk, merkle_root)
            .ok_or(Reason::TaprootTweakUndefined)?;
        let pk = *pk + Point::generator() * t;
        let pk = NonZero::from_point(pk).ok_or(Reason::TaprootChildPkZero)?;

        // Taproot: Normalize the public key again after taproot tweak
        C::normalize_point(pk)
    } else {
        pk
    };

    let mut comm_list = signers
        .iter()
        .map(|(j, comm, _sig_share)| {
            utils::share_preimage(vss_setup, *j)
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
    let binding_factor_list = utils::compute_binding_factors::<C>(*pk, &comm_list, msg);
    let group_commitment = C::normalize_point(utils::compute_group_commitment::<C>(
        &comm_list,
        &binding_factor_list,
    ));
    let z = signers
        .iter()
        .map(|(_j, _comm, sig_share)| sig_share.0)
        .sum();

    let sig = Signature {
        r: group_commitment,
        z,
    };
    sig.verify(&pk, msg).map_err(|_| Reason::InvalidSig)?;

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
    HdChildPkZero,
    #[cfg(feature = "taproot")]
    MissingTaprootMerkleRoot,
    #[cfg(feature = "taproot")]
    NonTaprootCiphersuite,
    #[cfg(feature = "taproot")]
    TaprootTweakUndefined,
    #[cfg(feature = "taproot")]
    TaprootChildPkZero,
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
            Reason::HdChildPkZero => f.write_str("HD derivation error: child pk is zero"),
            #[cfg(feature = "taproot")]
            Reason::MissingTaprootMerkleRoot => f.write_str(
                "taproot merkle tree is missing: it must be specified \
                for taproot ciphersuite via `SigningOptions::set_taproot_tweak`",
            ),
            #[cfg(feature = "taproot")]
            Reason::NonTaprootCiphersuite => {
                f.write_str("ciphersuite doesn't support taproot tweaks")
            }
            #[cfg(feature = "taproot")]
            Reason::TaprootTweakUndefined => f.write_str("taproot tweak is undefined"),
            #[cfg(feature = "taproot")]
            Reason::TaprootChildPkZero => f.write_str("taproot tweak: child pk is zero"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AggregateError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            Reason::UnknownSigner(_)
            | Reason::SameSignerTwice
            | Reason::InvalidSig
            | Reason::HdChildPkZero => None,
            #[cfg(feature = "taproot")]
            Reason::MissingTaprootMerkleRoot
            | Reason::NonTaprootCiphersuite
            | Reason::TaprootTweakUndefined
            | Reason::TaprootChildPkZero => None,
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
