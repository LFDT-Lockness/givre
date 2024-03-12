use super::{Ciphersuite, Secp256k1};

/// FROST ciphersuite that outputs [BIP-340] compliant sigantures
///
/// # Normalized public keys
/// BIP-340 requires that public keys are normalized, meaning that they must have
/// odd Y coordinate. Generic DKG protocols output public key with both even and odd
/// Y coordinate. You can use [`normalize_key_share`](super::normalize_key_share)
/// to normalize the key share after it's generated.
///
/// [BIP-340]: https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki
#[derive(Debug, Clone, Copy)]
pub struct Bitcoin;

impl Ciphersuite for Bitcoin {
    const NAME: &'static str = "DFNS-bitcoin-SHA256-v1";
    type Curve = <Secp256k1 as Ciphersuite>::Curve;
    type Digest = <Secp256k1 as Ciphersuite>::Digest;

    fn h1(msg: &[&[u8]]) -> generic_ec::Scalar<Self::Curve> {
        Secp256k1::h1(msg)
    }

    fn compute_challenge(
        group_commitment: &super::NormalizedPoint<Self>,
        group_public_key: &super::NormalizedPoint<Self>,
        msg: &[u8],
    ) -> generic_ec::Scalar<Self::Curve> {
        use sha2::{Digest, Sha256};
        static HASH: once_cell::sync::Lazy<Sha256> = once_cell::sync::Lazy::new(|| {
            let tag = Sha256::digest("BIP0340/challenge");
            Sha256::new().chain_update(tag).chain_update(tag)
        });
        let challenge = HASH
            .clone()
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
    fn serialize_point(point: &generic_ec::Point<Self::Curve>) -> Self::PointBytes {
        Secp256k1::serialize_point(point)
    }
    fn deserialize_point(
        bytes: &[u8],
    ) -> Result<generic_ec::Point<Self::Curve>, generic_ec::errors::InvalidPoint> {
        Secp256k1::deserialize_point(bytes)
    }

    type ScalarBytes = <Secp256k1 as Ciphersuite>::ScalarBytes;
    fn serialize_scalar(scalar: &generic_ec::Scalar<Self::Curve>) -> Self::ScalarBytes {
        scalar.to_be_bytes()
    }
    fn deserialize_scalar(
        bytes: &[u8],
    ) -> Result<generic_ec::Scalar<Self::Curve>, generic_ec::errors::InvalidScalar> {
        generic_ec::Scalar::from_be_bytes(bytes)
    }

    fn is_normalized(point: &generic_ec::Point<Self::Curve>) -> bool {
        // First byte of compressed point is either 2 or 3. 2 means the Y coordinate is odd.
        debug_assert!(matches!(point.to_bytes(true)[0], 2 | 3));
        point.to_bytes(true)[0] == 2
    }

    type NormalizedPointBytes = [u8; 32];
    fn serialize_normalized_point(
        point: &super::NormalizedPoint<Self>,
    ) -> Self::NormalizedPointBytes {
        #[allow(clippy::expect_used)]
        (**point).to_bytes(true)[1..]
            .try_into()
            .expect("the size doesn't match")
    }
}
