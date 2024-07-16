//! Round 2 - Signing
//!
//! In the second round, each signer signs a message and obtains a [signature share](SigShare).
//!
//! For more details, refer to [parent module](super) docs, or [Section 5.2] of the draft.
//!
//! [Section 5.2]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html#name-round-two-signature-share-g

use alloc::{borrow::Cow, vec::Vec};
use core::{fmt, iter};
use key_share::VssSetup;

use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};

use crate::{
    ciphersuite::{Ciphersuite, NormalizedPoint},
    KeyShare, SignerIndex,
};

use super::{
    round1::{PublicCommitments, SecretNonces},
    utils,
};

/// Partial signature
#[derive(Debug, Copy, Clone)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound = "")
)]
pub struct SigShare<E: Curve>(pub Scalar<E>);

/// Signing options
///
/// Like [`sign`] but allows to specify additional options like the HD derivation path
pub struct SigningOptions<'a, C: Ciphersuite> {
    key_share: &'a KeyShare<C::Curve>,
    nonce: SecretNonces<C::Curve>,
    msg: &'a [u8],
    signers: &'a [(SignerIndex, PublicCommitments<C::Curve>)],

    /// Additive shift derived from HD path
    hd_additive_shift: Option<Scalar<C::Curve>>,
    /// Possible values:
    /// * `None` if script tree is empty
    /// * `Some(root)` if script tree is not empty
    ///
    /// It only takes effect when `C::IS_TAPROOT` is `true`
    taproot_merkle_root: Option<[u8; 32]>,
}

impl<'a, C: Ciphersuite> SigningOptions<'a, C> {
    /// Constructs signing options
    ///
    /// Takes:
    /// * `key_share` which will be used for signing
    /// * Secret `nonce` from [round 1](super::round1)
    /// * `msg` to be signed
    /// * List of `signers`: their indexes `0 <= i < n` that were used at keygen,
    ///   and their commitments to the nonces obtained at [round 1](super::round1)
    ///
    /// Outputs `SigningOptions` which can be used to specify optional parameters and carry out signing.
    ///
    /// **Never reuse nonces!** Using the same nonce to sign two different messages leaks the secret share.
    pub fn new(
        key_share: &'a KeyShare<C::Curve>,
        nonce: SecretNonces<C::Curve>,
        msg: &'a [u8],
        signers: &'a [(SignerIndex, PublicCommitments<C::Curve>)],
    ) -> Self {
        Self {
            key_share,
            nonce,
            msg,
            signers,
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
        mut self,
        path: impl IntoIterator<Item = Index>,
    ) -> Result<Self, crate::key_share::HdError<<slip_10::NonHardenedIndex as TryFrom<Index>>::Error>>
    where
        slip_10::NonHardenedIndex: TryFrom<Index>,
    {
        use crate::key_share::HdError;

        let public_key = self
            .key_share
            .extended_public_key()
            .ok_or(HdError::DisabledHd)?;
        self.hd_additive_shift =
            Some(utils::derive_additive_shift(public_key, path).map_err(HdError::InvalidPath)?);
        Ok(self)
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
    ) -> Result<Self, SigningError> {
        if !C::IS_TAPROOT {
            return Err(Reason::NonTaprootCiphersuite.into());
        }

        self.taproot_merkle_root = merkle_root;
        Ok(self)
    }

    /// Issues a partial signature with provided options
    ///
    /// Outputs a partial signature.
    pub fn sign(self) -> Result<SigShare<C::Curve>, SigningError> {
        sign_inner::<C>(
            self.key_share,
            self.hd_additive_shift,
            self.taproot_merkle_root,
            self.nonce,
            self.msg,
            self.signers,
        )
    }
}

/// Issues a partial signature on the `msg`
///
/// Inputs:
/// * `key_share` which will be used for signing
/// * Secret `nonce` from [round 1](super::round1)
/// * `msg` to be signed
/// * List of `signers`: their indexes `0 <= i < n` that were used at keygen,
///   and their commitments to the nonces obtained at [round 1](super::round1)
///
/// Outputs a partial signature.
///
/// **Never reuse nonces!** Using the same nonce to sign two different messages leaks the secret share.
///
/// If you need to specify additional parameters such as HD derivation path or taproot merkle root,
/// use [`SigningOptions`] instead.
pub fn sign<C: Ciphersuite>(
    key_share: &KeyShare<C::Curve>,
    nonce: SecretNonces<C::Curve>,
    msg: &[u8],
    signers: &[(SignerIndex, PublicCommitments<C::Curve>)],
) -> Result<SigShare<C::Curve>, SigningError> {
    SigningOptions::<C>::new(key_share, nonce, msg, signers).sign()
}

/// Issues a partial signature on the `msg`
///
/// Inputs:
/// * `key_share` which will be used for signing
/// * `hd_additive_nonce` derived from HD derivation path
/// * `taproot_merkle_tree` for taproot tweak (which only takes effect if `C::IS_TAPROOT` is `true`)
/// * Secret `nonce` from [round 1](super::round1)
/// * `msg` to be signed
/// * List of `signers`: their indexes `0 <= i < n` that were used at keygen,
///   and their commitments to the nonces obtained at [round 1](super::round1)
///
/// Outputs a partial signature.
///
/// **Never reuse nonces!** Using the same nonce to sign two different messages leaks the secret share.
fn sign_inner<C: Ciphersuite>(
    key_share: &KeyShare<C::Curve>,
    hd_additive_shift: Option<Scalar<C::Curve>>,
    #[rustfmt::skip]
    #[cfg_attr(not(feature = "taproot"), allow(unused_variables))]
    taproot_merkle_root: Option<[u8; 32]>,
    nonce: SecretNonces<C::Curve>,
    msg: &[u8],
    signers: &[(SignerIndex, PublicCommitments<C::Curve>)],
) -> Result<SigShare<C::Curve>, SigningError> {
    // --- Retrieve and Validate Data
    let t = key_share.min_signers();
    let crate::key_share::DirtyKeyShare {
        i,
        key_info:
            crate::key_share::DirtyKeyInfo {
                shared_public_key: pk,
                vss_setup,
                ..
            },
        x,
    } = &**key_share;
    // Make sure we never use (potentially non-normalized) `key_share` anywhere
    // below by shadowing the variable.
    #[allow(unused_variables)]
    let key_share = ();

    // Derive HD child
    let (x, pk) = if let Some(additive_shift) = hd_additive_shift {
        apply_additive_shift(*i, vss_setup, Cow::Borrowed(x), *pk, additive_shift)
            .map_err(Reason::HdShift)?
    } else {
        (Cow::Borrowed(x), *pk)
    };

    // Taproot: Normalize the key share
    let (x, pk) = normalize_key_share(x, pk);

    #[cfg(feature = "taproot")]
    let (x, pk) = {
        // Taproot: tweak the key share
        let (x, pk) = if C::IS_TAPROOT {
            let t = crate::signing::taproot::tweak::<C>(pk, taproot_merkle_root)
                .ok_or(Reason::TaprootTweakUndefined)?;

            apply_additive_shift(*i, vss_setup, x, *pk, t).map_err(Reason::TaprootShift)?
        } else {
            (x, *pk)
        };

        // Taproot: Normalize the key share again after tweaking...
        normalize_key_share(x, pk)
    };

    if signers.len() < usize::from(t) {
        return Err(Reason::TooFewSigners {
            min_signers: t,
            n: signers.len(),
        }
        .into());
    }
    let signer_id = utils::share_preimage(vss_setup, *i).ok_or(Bug::RetrieveOwnShareId)?;
    let mut comm_list = signers
        .iter()
        .map(|(j, comm)| {
            if i == j && nonce.public_commitments() != *comm {
                // Commitments don't match provided nonces - invalid inputs
                Err(Reason::NoncesDontMatchComm)
            } else {
                utils::share_preimage(vss_setup, *j)
                    .map(|id| (id, *comm))
                    .ok_or(Reason::UnknownSigner(*j))
            }
        })
        .collect::<Result<Vec<_>, _>>()?;
    comm_list.sort_unstable_by_key(|(i, _)| *i);

    // Check that:
    // 1. This signer id is in the list of participants
    // 2. No signer appears in the list more than once
    //
    // Given that the list is sorted, the check can be done in one iteration
    let mut own_index_found = None;
    for (signer_index, ((j, _), com_j_minus_one)) in comm_list
        .iter()
        .zip(iter::once(None).chain(comm_list.iter().map(Some)))
        .enumerate()
    {
        if *j == signer_id {
            own_index_found = Some(signer_index);
        }
        if let Some((j_minus_one, _)) = com_j_minus_one {
            if j_minus_one == j {
                return Err(Reason::SameSignerTwice.into());
            }
        }
    }
    let Some(i) = own_index_found else {
        return Err(Reason::SignerNotInList.into());
    };

    // --- The Signing
    let binding_factor_list = utils::compute_binding_factors::<C>(*pk, &comm_list, msg);
    let binding_factor = binding_factor_list.get(i).ok_or(Bug::OwnBindingFactor)?.1;
    debug_assert_eq!(binding_factor_list[i].0, signer_id);

    let group_commitment = utils::compute_group_commitment::<C>(&comm_list, &binding_factor_list);
    let nonce_share = nonce.hiding_nonce + (nonce.binding_nonce * binding_factor);

    let (group_commitment, nonce_share) = match NormalizedPoint::try_normalize(group_commitment) {
        Ok(group_commitment) => {
            // Signature is normalized, no need to do anything else
            (group_commitment, nonce_share)
        }
        Err(neg_group_commitment) => {
            // Signature is not normalized, we had to negate `group_commitment`. Each signer need to negate
            // their `nonce_share` as well
            (neg_group_commitment, -nonce_share)
        }
    };

    let signers_list = comm_list.iter().map(|(i, _)| *i).collect::<Vec<_>>();
    let lambda_i = if vss_setup.is_some() {
        derive_interpolating_value(&signers_list, &signer_id)
            .ok_or(Reason::DeriveInterpolationValue)?
    } else {
        Scalar::one()
    };

    let challenge = C::compute_challenge(&group_commitment, &pk, msg);

    Ok(SigShare(nonce_share + (lambda_i * &*x * challenge)))
}

/// Computes an interpolation value as described in [Section 4.2]
///
/// [Section 4.2]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html#name-polynomials
///
/// Differences compared to the draft:
/// * List of signers **must be** sorted (the draft doesn't require this) \
///   Function enforces a debug assertation to make sure that list of signers is sorted.
/// * Implemented minor optimizations that allow iterate over list of signers only once by
///   employing the fact that list of signers is sorted.
fn derive_interpolating_value<E: Curve>(
    signers_list: &[NonZero<Scalar<E>>],
    x_i: &NonZero<Scalar<E>>,
) -> Option<Scalar<E>> {
    debug_assert!(
        utils::is_sorted(signers_list),
        "signers list must be sorted"
    );

    let mut x_i_observed = false;

    let mut num = Scalar::one();
    let mut denom = NonZero::<Scalar<E>>::one();

    for (x_j, x_j_minus_one) in signers_list
        .iter()
        .zip(iter::once(None).chain(signers_list.iter().map(Some)))
    {
        if Some(x_j) == x_j_minus_one {
            return None;
        }
        let Some(substraction) = NonZero::from_scalar(x_j - x_i) else {
            // x_i equals to x_j
            x_i_observed = true;
            continue;
        };
        num *= x_j.as_ref();
        denom *= substraction;
    }

    if !x_i_observed {
        return None;
    }

    Some(num * denom.invert())
}

fn apply_additive_shift<'a, E: Curve>(
    i: u16,
    vss_setup: &Option<VssSetup<E>>,
    x: Cow<'a, NonZero<SecretScalar<E>>>,
    pk: NonZero<Point<E>>,
    additive_shift: Scalar<E>,
) -> Result<(Cow<'a, NonZero<SecretScalar<E>>>, NonZero<Point<E>>), ApplyAdditiveShiftError> {
    let pk = pk + Point::generator() * additive_shift;
    let pk = NonZero::from_point(pk).ok_or(ApplyAdditiveShiftError::ChildPkZero)?;

    if vss_setup.is_some() || i == 0 {
        // Only following key shares are modified:
        // 1. For polynomial key shares, each key share is shifted
        // 2. For additive key share, only the key share of signer i=0 is shifted

        let x = SecretScalar::new(&mut (&*x + additive_shift));
        let x = NonZero::from_secret_scalar(x).ok_or(ApplyAdditiveShiftError::ChildShareZero)?;
        Ok((Cow::Owned(x), pk))
    } else {
        Ok((x, pk))
    }
}

fn normalize_key_share<C: Ciphersuite>(
    x: Cow<NonZero<SecretScalar<C::Curve>>>,
    pk: NonZero<Point<C::Curve>>,
) -> (
    Cow<NonZero<SecretScalar<C::Curve>>>,
    NormalizedPoint<C, NonZero<Point<C::Curve>>>,
) {
    match NormalizedPoint::<C, _>::try_normalize(pk) {
        Ok(pk) => {
            // public key is already normalized, there's nothing to do
            (x, pk)
        }

        Err(neg_pk) => {
            // public key was not normalized. we need to negate the key share.
            // note that we do not negate `public_shares` as they are not used
            // anywhere in the round 2 of signing.
            (Cow::Owned(-&*x), neg_pk)
        }
    }
}

/// Signing error
#[derive(Debug)]
pub struct SigningError(Reason);

#[derive(Debug)]
enum Reason {
    #[cfg(feature = "taproot")]
    NonTaprootCiphersuite,
    TooFewSigners {
        min_signers: u16,
        n: usize,
    },
    UnknownSigner(SignerIndex),
    SameSignerTwice,
    SignerNotInList,
    NoncesDontMatchComm,
    DeriveInterpolationValue,
    HdShift(ApplyAdditiveShiftError),
    #[cfg(feature = "taproot")]
    TaprootTweakUndefined,
    #[cfg(feature = "taproot")]
    TaprootShift(ApplyAdditiveShiftError),
    Bug(Bug),
}

#[derive(Debug)]
enum ApplyAdditiveShiftError {
    ChildPkZero,
    ChildShareZero,
}

#[derive(Debug)]
enum Bug {
    RetrieveOwnShareId,
    OwnBindingFactor,
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            #[cfg(feature = "taproot")]
            Reason::NonTaprootCiphersuite => write!(f, "ciphersuite doesn't support taproot"),
            Reason::TooFewSigners { min_signers, n } => write!(
                f,
                "signers list contains {n} signers, although at \
                least {min_signers} must take part in the signing"
            ),
            Reason::UnknownSigner(j) => write!(f, "unknown signer with index {j}"),
            Reason::SameSignerTwice => f.write_str(
                "same signer appears more than once in the list \
                of signers",
            ),
            Reason::SignerNotInList => f.write_str("signer not in the list of participants"),
            Reason::NoncesDontMatchComm => f.write_str("nonces don't match signer commitments"),
            Reason::DeriveInterpolationValue => f.write_str(
                "invalid list of signers: either this signer is \
                not in the list, or some signer in the list is \
                mentioned more than once",
            ),
            Reason::HdShift(_) => f.write_str("HD derivation: apply additive shift"),
            #[cfg(feature = "taproot")]
            Reason::TaprootShift(_) => f.write_str("taproot tweak: apply additive shift"),
            #[cfg(feature = "taproot")]
            Reason::TaprootTweakUndefined => f.write_str("taproot tweak is undefined"),
            Reason::Bug(_) => f.write_str("bug occurred"),
        }
    }
}

impl fmt::Display for ApplyAdditiveShiftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ChildPkZero => f.write_str("HD wallet derivation: child pk is zero"),
            Self::ChildShareZero => f.write_str("HD wallet derivation: child share is zero"),
        }
    }
}

impl fmt::Display for Bug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bug::RetrieveOwnShareId => f.write_str("retrieve own share id"),
            Bug::OwnBindingFactor => f.write_str("retrieve own binding factor"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SigningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            Reason::TooFewSigners { .. }
            | Reason::UnknownSigner(_)
            | Reason::NoncesDontMatchComm
            | Reason::DeriveInterpolationValue
            | Reason::SameSignerTwice
            | Reason::SignerNotInList => None,
            #[cfg(feature = "taproot")]
            Reason::NonTaprootCiphersuite | Reason::TaprootTweakUndefined => None,
            #[cfg(feature = "taproot")]
            Reason::TaprootShift(err) => Some(err),
            Reason::Bug(bug) => Some(bug),
            Reason::HdShift(err) => Some(err),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ApplyAdditiveShiftError {}

#[cfg(feature = "std")]
impl std::error::Error for Bug {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Bug::RetrieveOwnShareId | Bug::OwnBindingFactor => None,
        }
    }
}

impl From<Reason> for SigningError {
    fn from(err: Reason) -> Self {
        SigningError(err)
    }
}
impl From<Bug> for SigningError {
    fn from(err: Bug) -> Self {
        SigningError(Reason::Bug(err))
    }
}
