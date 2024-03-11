//! Round 2 - Signing
//!
//! In the second round, each signer signs a message and obtains a [signature share](SigShare).
//!
//! For more details, refer to [parent module](super) docs, or [Section 5.2] of the draft.
//!
//! [Section 5.2]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html#name-round-two-signature-share-g

use core::{fmt, iter};

use generic_ec::{Curve, NonZero, Scalar};

use crate::{ciphersuite::Ciphersuite, KeyShare, SignerIndex};

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
pub fn sign<C: Ciphersuite>(
    key_share: &KeyShare<C::Curve>,
    nonce: SecretNonces<C::Curve>,
    msg: &[u8],
    signers: &[(SignerIndex, PublicCommitments<C::Curve>)],
) -> Result<SigShare<C::Curve>, SigningError> {
    // --- Retrieve and Validate Data
    if signers.len() < usize::from(key_share.min_signers()) {
        return Err(Reason::TooFewSigners {
            min_signers: key_share.min_signers(),
            n: signers.len(),
        }
        .into());
    }
    let signer_id = key_share
        .share_preimage(key_share.i)
        .ok_or(Bug::RetrieveOwnShareId)?;
    let mut comm_list = signers
        .iter()
        .map(|(j, comm)| {
            if key_share.i == *j && nonce.public_commitments() != *comm {
                // Commitments don't match provided nonces - invalid inputs
                Err(Reason::NoncesDontMatchComm)
            } else {
                key_share
                    .share_preimage(*j)
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
    let binding_factor_list =
        utils::compute_binding_factors::<C>(key_share.shared_public_key, &comm_list, msg);
    let binding_factor = binding_factor_list.get(i).ok_or(Bug::OwnBindingFactor)?.1;
    debug_assert_eq!(binding_factor_list[i].0, signer_id);

    let group_commitment = utils::compute_group_commitment(&comm_list, &binding_factor_list);

    let signers_list = comm_list.iter().map(|(i, _)| *i).collect::<Vec<_>>();
    let lambda_i = if key_share.vss_setup.is_some() {
        derive_interpolating_value(&signers_list, &signer_id)
            .ok_or(Reason::DeriveInterpolationValue)?
    } else {
        Scalar::one()
    };

    let challenge = C::compute_challenge(&group_commitment, &key_share.shared_public_key, msg);

    Ok(SigShare(
        nonce.hiding_nonce
            + (nonce.binding_nonce * binding_factor)
            + (lambda_i * &key_share.x * challenge),
    ))
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
        denom = denom * substraction;
    }

    if !x_i_observed {
        return None;
    }

    Some(num * denom.invert())
}

/// Signing error
#[derive(Debug)]
pub struct SigningError(Reason);

#[derive(Debug)]
enum Reason {
    TooFewSigners { min_signers: u16, n: usize },
    UnknownSigner(SignerIndex),
    SameSignerTwice,
    SignerNotInList,
    NoncesDontMatchComm,
    DeriveInterpolationValue,
    Bug(Bug),
}

#[derive(Debug)]
enum Bug {
    RetrieveOwnShareId,
    OwnBindingFactor,
}

impl fmt::Display for SigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Reason::TooFewSigners { min_signers, n } => write!(
                f,
                "signers list contains {n} singners, although at \
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
            Reason::Bug(_) => f.write_str("bug occurred"),
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

impl std::error::Error for SigningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            Reason::TooFewSigners { .. }
            | Reason::UnknownSigner(_)
            | Reason::NoncesDontMatchComm
            | Reason::DeriveInterpolationValue
            | Reason::SameSignerTwice
            | Reason::SignerNotInList => None,
            Reason::Bug(bug) => Some(bug),
        }
    }
}

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
