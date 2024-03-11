//! FROST Ciphersuite
//!
//! Ciphersuite specifies which curve and hash primitives to use during the signing.
//!
//! Out of the box, we provide ciphersuites defined the in the draft:
//! * [Secp256k1], requires `ciphersuite-secp256k1` feature
//! * [Ed25519], requires `ciphersuite-ed25519` feature
use generic_ec::{
    errors::{InvalidPoint, InvalidScalar},
    Curve, Point, Scalar, SecretScalar,
};
use rand_core::{CryptoRng, RngCore};

#[cfg(feature = "ciphersuite-ed25519")]
mod ed25519;
#[cfg(feature = "ciphersuite-secp256k1")]
mod secp256k1;

#[cfg(feature = "ciphersuite-ed25519")]
pub use ed25519::Ed25519;
#[cfg(feature = "ciphersuite-secp256k1")]
pub use secp256k1::Secp256k1;

/// Ciphersuite determines an underlying curve and set of cryptographic primitives
/// used in the protocol
///
/// For the details, refer to [Section 6] of the draft
///
/// [Section 6]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html#name-ciphersuites
pub trait Ciphersuite {
    /// Name of the ciphersuite, also known as `contextString` in the draft
    const NAME: &'static str;

    /// Underlying curve on which signatures will be produced
    type Curve: Curve;

    /// Digest that's used to feed data into [H4](Self::h4) and [H5](Self::h5) hash functions
    type Digest: digest::Update + digest::FixedOutput + Clone;

    /// `H1` hash function as defined in the draft
    ///
    /// Accepts a list of bytestring, that'll be contatenated before hashing.
    /// Returns `H1(data[0] || data[1] || ... || data[data.len() - 1])`.
    fn h1(msg: &[&[u8]]) -> Scalar<Self::Curve>;
    /// Computes the challenge according to Schnorr scheme
    ///
    /// Implementation should be based on `H2` hash function as defined in the draft.
    fn compute_challenge(
        group_commitment: &Point<Self::Curve>,
        group_public_key: &Point<Self::Curve>,
        msg: &[u8],
    ) -> Scalar<Self::Curve>;
    /// `H3` hash function as defined in the draft
    ///
    /// Accepts a list of bytestring, that'll be contatenated before hashing.
    /// Returns `H3(data[0] || data[1] || ... || data[data.len() - 1])`.
    fn h3(msg: &[&[u8]]) -> Scalar<Self::Curve>;

    /// `H4` hash function as defined in the draft
    ///
    /// Accepts a list of bytestring, that'll be contatenated before hashing.
    /// Returns `H4(data[0] || data[1] || ... || data[data.len() - 1])`.
    fn h4() -> Self::Digest;
    /// `H5` hash function as defined in the draft
    ///
    /// Accepts a list of bytestring, that'll be contatenated before hashing.
    /// Returns `H5(data[0] || data[1] || ... || data[data.len() - 1])`.
    fn h5() -> Self::Digest;

    /// Byte array that contains bytes representation of the point
    type PointBytes: AsRef<[u8]>;
    /// Serializes point
    fn serialize_point(point: &Point<Self::Curve>) -> Self::PointBytes;
    /// Deserializes point
    fn deserialize_point(bytes: &[u8]) -> Result<Point<Self::Curve>, InvalidPoint>;

    /// Byte array that contains bytes representation of the scalar
    type ScalarBytes: AsRef<[u8]>;
    /// Serializes scalar
    fn serialize_scalar(scalar: &Scalar<Self::Curve>) -> Self::ScalarBytes;
    /// Deserializes scalar
    fn deserialize_scalar(bytes: &[u8]) -> Result<Scalar<Self::Curve>, InvalidScalar>;
    /// Deserializes secret scalar
    fn deserialize_secret_scalar(bytes: &[u8]) -> Result<SecretScalar<Self::Curve>, InvalidScalar> {
        let mut scalar = Self::deserialize_scalar(bytes)?;
        Ok(SecretScalar::new(&mut scalar))
    }
}

/// Nonce generation as defined in [Section 4.1](https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html#name-nonce-generation)
///
/// The draft specifies that this function should only accept a scalar as `additional_entropy`, however,
/// we observed that any data that's only known to the signer can be fed into this function.
pub fn generate_nonce<C: Ciphersuite>(
    rng: &mut (impl RngCore + CryptoRng),
    additional_entropy: impl AdditionalEntropy<C>,
) -> SecretScalar<C::Curve> {
    let mut random_bytes = [0u8; 32];
    rng.fill_bytes(&mut random_bytes);

    let additional_entropy = additional_entropy.to_bytes();

    let mut hash = C::h3(&[random_bytes.as_slice(), additional_entropy.as_ref()]);

    generic_ec::SecretScalar::new(&mut hash)
}

/// Additional entropy to [nonce generation](generate_nonce)
pub trait AdditionalEntropy<C: Ciphersuite> {
    /// Bytes arrays that fits the whole bytes representation of the entropy
    type Bytes<'b>: AsRef<[u8]>
    where
        Self: 'b;

    /// Returns bytes representation of the entropy encoded in complience with [`C`](Ciphersuite)
    fn to_bytes<'b>(&'b self) -> Self::Bytes<'b>;
}

impl<C: Ciphersuite<Curve = E>, E: Curve> AdditionalEntropy<C> for crate::KeyShare<E> {
    type Bytes<'b> = <SecretScalar<E> as AdditionalEntropy<C>>::Bytes<'b>;
    fn to_bytes<'b>(&'b self) -> Self::Bytes<'b> {
        AdditionalEntropy::<C>::to_bytes(&self.x)
    }
}
impl<C: Ciphersuite<Curve = E>, E: Curve> AdditionalEntropy<C> for generic_ec::Scalar<E> {
    type Bytes<'b> = C::ScalarBytes;
    fn to_bytes<'b>(&'b self) -> Self::Bytes<'b> {
        C::serialize_scalar(self)
    }
}
impl<C: Ciphersuite<Curve = E>, E: Curve> AdditionalEntropy<C> for generic_ec::SecretScalar<E> {
    type Bytes<'b> = <generic_ec::Scalar<E> as AdditionalEntropy<C>>::Bytes<'b>;
    fn to_bytes<'b>(&'b self) -> Self::Bytes<'b> {
        AdditionalEntropy::<C>::to_bytes(self.as_ref())
    }
}
impl<C: Ciphersuite> AdditionalEntropy<C> for [u8] {
    type Bytes<'b> = &'b [u8];
    fn to_bytes<'b>(&'b self) -> Self::Bytes<'b> {
        self
    }
}
impl<C: Ciphersuite, const N: usize> AdditionalEntropy<C> for [u8; N] {
    type Bytes<'b> = &'b [u8; N];
    fn to_bytes<'b>(&'b self) -> Self::Bytes<'b> {
        self
    }
}
impl<C: Ciphersuite, T: AdditionalEntropy<C>> AdditionalEntropy<C> for &T {
    type Bytes<'b> = <T as AdditionalEntropy<C>>::Bytes<'b> where Self: 'b;
    fn to_bytes<'b>(&'b self) -> Self::Bytes<'b> {
        (*self).to_bytes()
    }
}
