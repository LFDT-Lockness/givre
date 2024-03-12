use digest::Digest;

use crate::Ciphersuite;

/// FROST(Ed25519, SHA-512) ciphersuite that produces Ed25519-compliant signatures
#[derive(Debug, Clone, Copy)]
pub struct Ed25519;

impl Ciphersuite for Ed25519 {
    const NAME: &'static str = "FROST-ED25519-SHA512-v1";

    type Curve = generic_ec::curves::Ed25519;
    type Digest = sha2::Sha512;

    fn h1(msg: &[&[u8]]) -> generic_ec::Scalar<Self::Curve> {
        let mut hash = sha2::Sha512::new()
            .chain_update(Self::NAME)
            .chain_update(b"rho");
        for msg in msg {
            hash.update(msg);
        }
        let hash = hash.finalize();

        generic_ec::Scalar::from_le_bytes_mod_order(hash)
    }

    fn compute_challenge(
        group_commitment: &super::NormalizedPoint<Self>,
        group_public_key: &super::NormalizedPoint<Self>,
        msg: &[u8],
    ) -> generic_ec::Scalar<Self::Curve> {
        let hash = sha2::Sha512::new()
            .chain_update(Self::serialize_normalized_point(group_commitment))
            .chain_update(Self::serialize_normalized_point(group_public_key))
            .chain_update(msg)
            .finalize();

        generic_ec::Scalar::from_le_bytes_mod_order(hash)
    }

    fn h3(msg: &[&[u8]]) -> generic_ec::Scalar<Self::Curve> {
        let mut hash = sha2::Sha512::new()
            .chain_update(Self::NAME)
            .chain_update(b"nonce");
        for msg in msg {
            hash.update(msg);
        }
        let hash = hash.finalize();

        generic_ec::Scalar::from_le_bytes_mod_order(hash)
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
    fn serialize_scalar(scalar: &generic_ec::Scalar<Self::Curve>) -> Self::ScalarBytes {
        scalar.to_le_bytes()
    }
    fn deserialize_scalar(
        bytes: &[u8],
    ) -> Result<generic_ec::Scalar<Self::Curve>, generic_ec::errors::InvalidScalar> {
        generic_ec::Scalar::from_le_bytes(bytes)
    }

    type NormalizedPointBytes = Self::PointBytes;
    fn serialize_normalized_point(
        point: &super::NormalizedPoint<Self>,
    ) -> Self::NormalizedPointBytes {
        Self::serialize_point(point)
    }
}
