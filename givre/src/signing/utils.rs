use alloc::vec::Vec;

use digest::{FixedOutput, Update};
use generic_ec::{NonZero, Point, Scalar};

use crate::ciphersuite::Ciphersuite;

use super::round1::PublicCommitments;

/// Encodes a list of commitments as described in [Section 4.3]
///
/// [Section 4.3]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html#name-list-operations
///
/// Differences compared to the draft:
/// * Instead of returning encoded data as a string, it rather feeds it directly into the hash
pub fn encode_group_commitment_list<C: Ciphersuite>(
    mut output: C::Digest,
    commitment_list: &[(NonZero<Scalar<C::Curve>>, PublicCommitments<C::Curve>)],
) -> C::Digest {
    for (
        i,
        PublicCommitments {
            hiding_comm,
            binding_comm,
        },
    ) in commitment_list
    {
        output.update(C::serialize_scalar(i).as_ref());
        output.update(C::serialize_point(hiding_comm).as_ref());
        output.update(C::serialize_point(binding_comm).as_ref());
    }
    output
}

/// Computes binding factors as described in [Section 4.4]
///
/// [Section 4.4]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html#name-binding-factors-computation
///
/// As stated in the draft, `commitments_list` must be sorted in ascending order by identifier. The implementation
/// makes debug assertation to make sure it holds.
///
/// Although it's not mentioned in the draft, but note that output list is sorted by signer ID.
pub fn compute_binding_factors<C: Ciphersuite>(
    shared_pk: NonZero<Point<C::Curve>>,
    commitment_list: &[(NonZero<Scalar<C::Curve>>, PublicCommitments<C::Curve>)],
    msg: &[u8],
) -> Vec<(NonZero<Scalar<C::Curve>>, Scalar<C::Curve>)> {
    debug_assert!(
        is_sorted_by_key(commitment_list, |(i, _)| i),
        "commitments list must be sorted"
    );

    let pk_bytes = C::serialize_point(&shared_pk);
    let msg_hash = C::h4().chain(msg).finalize_fixed();
    let encoded_commitment_hash =
        encode_group_commitment_list::<C>(C::h5(), commitment_list).finalize_fixed();

    let mut binding_factor_list = Vec::with_capacity(commitment_list.len());
    for (i, _) in commitment_list {
        let binding_factor = C::h1(&[
            pk_bytes.as_ref(),
            &msg_hash,
            &encoded_commitment_hash,
            C::serialize_scalar(i).as_ref(),
        ]);
        binding_factor_list.push((*i, binding_factor))
    }

    binding_factor_list
}

/// Computes a group commitment as described in [Section 4.5]
///
/// [Section 4.5]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html#name-group-commitment-computatio
///
/// Differences compared to the draft:
/// * Assumes that commitments and binding factors come in the same order, i.e. `commitment_list[i].0 == binding_factor_list[i].0`
///   for all i. Assumtion is enforced via debug assertation.
pub fn compute_group_commitment<C: Ciphersuite>(
    commitment_list: &[(NonZero<Scalar<C::Curve>>, PublicCommitments<C::Curve>)],
    binding_factor_list: &[(NonZero<Scalar<C::Curve>>, Scalar<C::Curve>)],
) -> Point<C::Curve> {
    use generic_ec::multiscalar::MultiscalarMul;
    debug_assert_eq!(commitment_list.len(), binding_factor_list.len());

    // binding_nonces = \sum_i commitment_list[i].1.binding_comm * binding_factor_list[i].1
    let binding_nonces =
        C::MultiscalarMul::multiscalar_mul(commitment_list.iter().zip(binding_factor_list).map(
            |((i, comm), (_i, factor))| {
                debug_assert_eq!(i, _i);
                (*factor, comm.binding_comm)
            },
        ));
    binding_nonces
        + commitment_list
            .iter()
            .map(|(_, comm)| comm.hiding_comm)
            .sum::<Point<_>>()
}

pub fn is_sorted<T: Ord>(slice: &[T]) -> bool {
    is_sorted_by_key(slice, |x| x)
}

pub fn is_sorted_by_key<T, B, F>(slice: &[T], f: F) -> bool
where
    F: Fn(&T) -> &B,
    B: Ord,
{
    slice.windows(2).all(|win| f(&win[0]) <= f(&win[1]))
}

/// Returns share preimage associated with j-th signer
///
/// * For additive shares, share preimage is defined as `j+1`
/// * For VSS-shares, share preimage is scalar $I_j$ such that $x_j = F(I_j)$ where
///   $F(x)$ is polynomial co-shared by the signers and $x_j$ is secret share of j-th
///   signer
pub fn share_preimage<E: generic_ec::Curve>(
    vss_setup: &Option<crate::key_share::VssSetup<E>>,
    j: u16,
) -> Option<NonZero<Scalar<E>>> {
    match vss_setup {
        Some(v) => v.I.get(usize::from(j)).copied(),
        None => Some(
            #[allow(clippy::expect_used)]
            NonZero::from_scalar(Scalar::from(j + 1)).expect("j+1 is guaranteed to be non-zero"),
        ),
    }
}

#[cfg(feature = "hd-wallets")]
pub fn derive_additive_shift<E: generic_ec::Curve, Index>(
    mut epub: slip_10::ExtendedPublicKey<E>,
    path: impl IntoIterator<Item = Index>,
) -> Result<Scalar<E>, <Index as TryInto<slip_10::NonHardenedIndex>>::Error>
where
    slip_10::NonHardenedIndex: TryFrom<Index>,
{
    let mut additive_shift = Scalar::<E>::zero();

    for child_index in path {
        let child_index: slip_10::NonHardenedIndex = child_index.try_into()?;
        let shift = slip_10::derive_public_shift(&epub, child_index);

        additive_shift += shift.shift;
        epub = shift.child_public_key;
    }

    Ok(additive_shift)
}
