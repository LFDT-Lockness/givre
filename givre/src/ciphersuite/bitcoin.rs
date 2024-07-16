use generic_ec::{NonZero, Point};
use sha2::Digest;

use super::{Ciphersuite, Secp256k1};

/// FROST ciphersuite that outputs [BIP-340] compliant signatures
///
/// [BIP-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
#[derive(Debug, Clone, Copy)]
pub struct Bitcoin;

impl Ciphersuite for Bitcoin {
    const NAME: &'static str = "DFNS-bitcoin-SHA256-v1";
    type Curve = <Secp256k1 as Ciphersuite>::Curve;
    type Digest = <Secp256k1 as Ciphersuite>::Digest;
    type MultiscalarMul = generic_ec::multiscalar::Default;

    const IS_TAPROOT: bool = true;

    fn h1(msg: &[&[u8]]) -> generic_ec::Scalar<Self::Curve> {
        Secp256k1::h1(msg)
    }

    fn compute_challenge(
        group_commitment: &super::NormalizedPoint<Self, Point<Self::Curve>>,
        group_public_key: &super::NormalizedPoint<Self, NonZero<Point<Self::Curve>>>,
        msg: &[u8],
    ) -> generic_ec::Scalar<Self::Curve> {
        let challenge = challenge_hash()
            .chain_update(group_commitment.to_bytes())
            .chain_update(group_public_key.to_bytes())
            .chain_update(msg)
            .finalize();
        generic_ec::Scalar::from_be_bytes_mod_order(challenge)
    }

    fn h3(msg: &[&[u8]]) -> generic_ec::Scalar<Self::Curve> {
        Secp256k1::h3(msg)
    }
    fn h4() -> Self::Digest {
        Secp256k1::h4()
    }
    fn h5() -> Self::Digest {
        Secp256k1::h5()
    }

    type PointBytes = <Secp256k1 as Ciphersuite>::PointBytes;
    fn serialize_point(point: &Point<Self::Curve>) -> Self::PointBytes {
        Secp256k1::serialize_point(point)
    }
    fn deserialize_point(
        bytes: &[u8],
    ) -> Result<Point<Self::Curve>, generic_ec::errors::InvalidPoint> {
        Secp256k1::deserialize_point(bytes)
    }

    type ScalarBytes = <Secp256k1 as Ciphersuite>::ScalarBytes;
    const SCALAR_SIZE: usize = 32;
    fn serialize_scalar(scalar: &generic_ec::Scalar<Self::Curve>) -> Self::ScalarBytes {
        scalar.to_be_bytes()
    }
    fn deserialize_scalar(
        bytes: &[u8],
    ) -> Result<generic_ec::Scalar<Self::Curve>, generic_ec::errors::InvalidScalar> {
        generic_ec::Scalar::from_be_bytes(bytes)
    }

    fn is_normalized(point: &Point<Self::Curve>) -> bool {
        // First byte of compressed non-zero point is either 2 or 3. 2 means the Y coordinate is odd.
        debug_assert!(point.is_zero() || matches!(point.to_bytes(true)[0], 2 | 3));
        point.is_zero() || point.to_bytes(true)[0] == 2
    }

    type NormalizedPointBytes = [u8; 32];
    const NORMALIZED_POINT_SIZE: usize = 32;
    fn serialize_normalized_point<P: AsRef<Point<Self::Curve>>>(
        point: &super::NormalizedPoint<Self, P>,
    ) -> Self::NormalizedPointBytes {
        #[allow(clippy::expect_used)]
        point.as_ref().to_bytes(true)[1..]
            .try_into()
            .expect("the size doesn't match")
    }
    fn deserialize_normalized_point(
        bytes: &[u8],
    ) -> Result<super::NormalizedPoint<Self, Point<Self::Curve>>, generic_ec::errors::InvalidPoint>
    {
        if bytes.len() != 32 {
            return Err(generic_ec::errors::InvalidPoint);
        }
        let mut buf = [0u8; 33];
        buf[0] = 2;
        buf[1..].copy_from_slice(bytes);

        let point = Self::deserialize_point(&buf)?;
        super::NormalizedPoint::try_normalize(point).map_err(|_| generic_ec::errors::InvalidPoint)
    }
}

#[cfg(feature = "std")]
fn challenge_hash() -> sha2::Sha256 {
    static PRECOMPUTED: std::sync::OnceLock<sha2::Sha256> = std::sync::OnceLock::new();
    PRECOMPUTED
        .get_or_init(|| {
            let tag = sha2::Sha256::digest("BIP0340/challenge");
            sha2::Sha256::new().chain_update(tag).chain_update(tag)
        })
        .clone()
}
#[cfg(not(feature = "std"))]
fn challenge_hash() -> sha2::Sha256 {
    let tag = sha2::Sha256::digest("BIP0340/challenge");
    sha2::Sha256::new().chain_update(&tag).chain_update(&tag)
}
