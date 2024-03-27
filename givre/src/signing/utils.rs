use alloc::vec::Vec;

use digest::{FixedOutput, Update};
use generic_ec::{Curve, NonZero, Point, Scalar};

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
pub fn compute_group_commitment<'a, E: Curve>(
    commitment_list: impl IntoIterator<Item = &'a (NonZero<Scalar<E>>, PublicCommitments<E>)>,
    binding_factor_list: impl IntoIterator<Item = &'a (NonZero<Scalar<E>>, Scalar<E>)>,
) -> Point<E> {
    commitment_list
        .into_iter()
        .zip(binding_factor_list)
        .map(|((i, comm), (_i, factor))| {
            debug_assert_eq!(i, _i);
            (*i, *comm, *factor)
        })
        .fold(Point::zero(), |acc, (_i, comm, binding_factor)| {
            let binding_nonce = comm.binding_comm * binding_factor;
            acc + comm.hiding_comm + binding_nonce
        })
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
