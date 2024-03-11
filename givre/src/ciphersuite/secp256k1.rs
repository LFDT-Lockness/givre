use digest::Digest;

use crate::Ciphersuite;

/// FROST(secp256k1, SHA-256) ciphersuite
#[derive(Debug, Clone, Copy)]
pub struct Secp256k1;

impl Ciphersuite for Secp256k1 {
    const NAME: &'static str = "FROST-secp256k1-SHA256-v1";

    type Curve = generic_ec::curves::Secp256k1;
    type Digest = sha2::Sha256;

    fn h1(msg: &[&[u8]]) -> generic_ec::Scalar<Self::Curve> {
        hash_to_scalar(msg, &[Self::NAME.as_bytes(), b"rho"])
    }

    fn h2(msg: &[&[u8]]) -> generic_ec::Scalar<Self::Curve> {
        hash_to_scalar(msg, &[Self::NAME.as_bytes(), b"chal"])
    }

    fn h3(msg: &[&[u8]]) -> generic_ec::Scalar<Self::Curve> {
        hash_to_scalar(msg, &[Self::NAME.as_bytes(), b"nonce"])
    }

    fn h4() -> Self::Digest {
        sha2::Sha256::new()
            .chain_update(Self::NAME)
            .chain_update(b"msg")
    }

    fn h5() -> Self::Digest {
        sha2::Sha256::new()
            .chain_update(Self::NAME)
            .chain_update(b"com")
    }

    type PointBytes = generic_ec::EncodedPoint<Self::Curve>;
    fn serialize_point(point: &generic_ec::Point<Self::Curve>) -> Self::PointBytes {
        point.to_bytes(true)
    }
    fn deserialize_point(
        bytes: &[u8],
    ) -> Result<generic_ec::Point<Self::Curve>, generic_ec::errors::InvalidPoint> {
        generic_ec::Point::from_bytes(bytes)
    }

    type ScalarBytes = generic_ec::EncodedScalar<Self::Curve>;
    fn serialize_scalar(scalar: &generic_ec::Scalar<Self::Curve>) -> Self::ScalarBytes {
        scalar.to_be_bytes()
    }
    fn deserialize_scalar(
        bytes: &[u8],
    ) -> Result<generic_ec::Scalar<Self::Curve>, generic_ec::errors::InvalidScalar> {
        generic_ec::Scalar::from_be_bytes(bytes)
    }
}

fn hash_to_scalar(
    msgs: &[&[u8]],
    dsts: &[&[u8]],
) -> generic_ec::Scalar<<Secp256k1 as Ciphersuite>::Curve> {
    use generic_ec::as_raw::FromRaw;
    use k256::elliptic_curve::{
        generic_array::typenum::Unsigned,
        hash2curve::{ExpandMsgXmd, FromOkm, GroupDigest as _},
    };

    // According to the doc, `k256::Secp256k1::hash_to_scalar` returns error if:
    // * dst.is_empty()
    // * len_in_bytes == 0
    // * len_in_bytes > u16::MAX
    // * len_in_bytes > 255 * HashT::OutputSize
    // where len_in_bytes = <Self::FieldElement as FromOkm>::Length

    // You can observe by looking at the module that `dst` is never empty, but also
    // we enforce it via debug assert below:
    debug_assert!(
        dsts.iter().map(|part| part.len()).sum::<usize>() > 0,
        "dst must not be empty"
    );

    // The other conditions are checked statically below
    #[allow(dead_code)]
    {
        const LENGTH_IN_BYTES: usize = <<k256::Scalar as FromOkm>::Length as Unsigned>::USIZE;
        const SHA256_OUTPUT_SIZE: usize =
            <<sha2::Sha256 as digest::OutputSizeUser>::OutputSize as Unsigned>::USIZE;
        use static_assertions as sa;

        sa::const_assert!(LENGTH_IN_BYTES > 0);
        sa::const_assert!(LENGTH_IN_BYTES <= u16::MAX as _);
        sa::const_assert!(LENGTH_IN_BYTES <= 255 * SHA256_OUTPUT_SIZE);
    }

    // So, we can safely unwrap the result
    #[allow(clippy::expect_used)]
    let scalar_raw = k256::Secp256k1::hash_to_scalar::<ExpandMsgXmd<sha2::Sha256>>(msgs, dsts)
        .expect("should never fail");
    generic_ec::Scalar::from_raw(generic_ec::curves::Secp256k1::scalar(scalar_raw))
}
