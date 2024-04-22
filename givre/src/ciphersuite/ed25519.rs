use digest::Digest;
use generic_ec::{NonZero, Point};

use crate::Ciphersuite;

/// FROST(Ed25519, SHA-512) ciphersuite that produces Ed25519-compliant signatures
#[derive(Debug, Clone, Copy)]
pub struct Ed25519;

impl Ciphersuite for Ed25519 {
    const NAME: &'static str = "FROST-ED25519-SHA512-v1";

    type Curve = generic_ec::curves::Ed25519;
    type Digest = sha2::Sha512;
    type MultiscalarMul = generic_ec::multiscalar::Dalek;

    fn h1(msg: &[&[u8]]) -> generic_ec::Scalar<Self::Curve> {
        let mut hash = sha2::Sha512::new()
            .chain_update(Self::NAME)
            .chain_update(b"rho");
        for msg in msg {
            hash.update(msg);
        }
        let hash = hash.finalize();

        reduce_512bits_le_scalar_mod_order(&hash.into())
    }

    fn compute_challenge(
        group_commitment: &super::NormalizedPoint<Self, Point<Self::Curve>>,
        group_public_key: &super::NormalizedPoint<Self, NonZero<Point<Self::Curve>>>,
        msg: &[u8],
    ) -> generic_ec::Scalar<Self::Curve> {
        let hash = sha2::Sha512::new()
            .chain_update(Self::serialize_normalized_point(group_commitment))
            .chain_update(Self::serialize_normalized_point(group_public_key))
            .chain_update(msg)
            .finalize();

        reduce_512bits_le_scalar_mod_order(&hash.into())
    }

    fn h3(msg: &[&[u8]]) -> generic_ec::Scalar<Self::Curve> {
        let mut hash = sha2::Sha512::new()
            .chain_update(Self::NAME)
            .chain_update(b"nonce");
        for msg in msg {
            hash.update(msg);
        }
        let hash = hash.finalize();

        reduce_512bits_le_scalar_mod_order(&hash.into())
    }

    fn h4() -> Self::Digest {
        sha2::Sha512::new()
            .chain_update(Self::NAME)
            .chain_update(b"msg")
    }

    fn h5() -> Self::Digest {
        sha2::Sha512::new()
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
    const SCALAR_SIZE: usize = 32;
    fn serialize_scalar(scalar: &generic_ec::Scalar<Self::Curve>) -> Self::ScalarBytes {
        scalar.to_le_bytes()
    }
    fn deserialize_scalar(
        bytes: &[u8],
    ) -> Result<generic_ec::Scalar<Self::Curve>, generic_ec::errors::InvalidScalar> {
        generic_ec::Scalar::from_le_bytes(bytes)
    }

    type NormalizedPointBytes = Self::PointBytes;
    const NORMALIZED_POINT_SIZE: usize = 32;
    fn serialize_normalized_point<P: AsRef<Point<Self::Curve>>>(
        point: &super::NormalizedPoint<Self, P>,
    ) -> Self::NormalizedPointBytes {
        Self::serialize_point(point.as_ref())
    }
    fn deserialize_normalized_point(
        bytes: &[u8],
    ) -> Result<super::NormalizedPoint<Self, Point<Self::Curve>>, generic_ec::errors::InvalidPoint>
    {
        let point = Self::deserialize_point(bytes)?;
        Ok(Self::normalize_point(point))
    }
}

/// Reduces 512 bits integer mod curve order
///
/// This is a more efficient version of [`generic_ec::Scalar::from_le_bytes_mod_order`]
fn reduce_512bits_le_scalar_mod_order(
    bytes: &[u8; 64],
) -> generic_ec::Scalar<generic_ec::curves::Ed25519> {
    let out = curve25519_dalek::Scalar::from_bytes_mod_order_wide(bytes);
    let out = generic_ec_curves::ed25519::Scalar(out);
    generic_ec::as_raw::FromRaw::from_raw(out)
}
