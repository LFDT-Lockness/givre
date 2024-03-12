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

#[cfg(feature = "ciphersuite-bitcoin")]
mod bitcoin;
#[cfg(feature = "ciphersuite-ed25519")]
mod ed25519;
#[cfg(feature = "ciphersuite-secp256k1")]
mod secp256k1;

#[cfg(feature = "ciphersuite-bitcoin")]
pub use bitcoin::Bitcoin;
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
pub trait Ciphersuite: Sized + Clone + Copy + core::fmt::Debug {
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
        group_commitment: &NormalizedPoint<Self>,
        group_public_key: &NormalizedPoint<Self>,
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

    /// Determines if the point is normalized according to the Schnorr scheme definition
    ///
    /// Some Schnorr schemes choose to work with X-only points such as public key and R-component
    /// of the signature. To enable that, Y coordinate of the points must be unambiguous. There are
    /// several ways of accomplishing that:
    ///
    /// 1. Implicitly choosing the Y coordinate that is in the lower half.
    /// 2. Implicitly choosing the Y coordinate that is even.
    /// 3. Implicitly choosing the Y coordinate that is a quadratic residue (i.e. has a square root modulo $p$).
    ///
    /// Our implementation of FROST requires that if point $X$ isn't normalized, then $-X$ is normalized. Note that
    /// certain parts of the protocol may enforce this property via debug assertations.
    ///
    /// The protocol always outputs sigantures with normalized R-component. We also require that public key is
    /// normalized. If it isn't, signing fails. You can use [`normalize_key_share`] function to normalize any key.
    ///
    /// If Schnorr scheme doesn't have a notion of normalized points, this function should always return `true`.
    fn is_normalized(point: &Point<Self::Curve>) -> bool {
        let _ = point;
        true
    }
    /// Normalizes the point
    ///
    /// Returns either `point` if it's already normalized, or `-point` otherwise. See [Ciphersuite::is_normalized]
    /// for more details.
    fn normalize_point(point: Point<Self::Curve>) -> NormalizedPoint<Self> {
        match NormalizedPoint::<Self>::try_from(point) {
            Ok(point) => point,
            Err(point) => point,
        }
    }
    /// Byte array that contains bytes representation of the normalized point
    type NormalizedPointBytes: AsRef<[u8]>;
    /// Serializes a normalized point in a space-efficient manner as defined by Schnorr scheme
    fn serialize_normalized_point(point: &NormalizedPoint<Self>) -> Self::NormalizedPointBytes;
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
    fn to_bytes(&self) -> Self::Bytes<'_>;
}

impl<C: Ciphersuite<Curve = E>, E: Curve> AdditionalEntropy<C> for crate::KeyShare<E> {
    type Bytes<'b> = <SecretScalar<E> as AdditionalEntropy<C>>::Bytes<'b>;
    fn to_bytes(&self) -> Self::Bytes<'_> {
        AdditionalEntropy::<C>::to_bytes(&self.x)
    }
}
impl<C: Ciphersuite<Curve = E>, E: Curve> AdditionalEntropy<C> for generic_ec::Scalar<E> {
    type Bytes<'b> = C::ScalarBytes;
    fn to_bytes(&self) -> Self::Bytes<'_> {
        C::serialize_scalar(self)
    }
}
impl<C: Ciphersuite<Curve = E>, E: Curve> AdditionalEntropy<C> for generic_ec::SecretScalar<E> {
    type Bytes<'b> = <generic_ec::Scalar<E> as AdditionalEntropy<C>>::Bytes<'b>;
    fn to_bytes(&self) -> Self::Bytes<'_> {
        AdditionalEntropy::<C>::to_bytes(self.as_ref())
    }
}
impl<C: Ciphersuite> AdditionalEntropy<C> for [u8] {
    type Bytes<'b> = &'b [u8];
    fn to_bytes(&self) -> Self::Bytes<'_> {
        self
    }
}
impl<C: Ciphersuite, const N: usize> AdditionalEntropy<C> for [u8; N] {
    type Bytes<'b> = &'b [u8; N];
    fn to_bytes(&self) -> Self::Bytes<'_> {
        self
    }
}
impl<C: Ciphersuite, T: AdditionalEntropy<C>> AdditionalEntropy<C> for &T {
    type Bytes<'b> = <T as AdditionalEntropy<C>>::Bytes<'b> where Self: 'b;
    fn to_bytes(&self) -> Self::Bytes<'_> {
        (*self).to_bytes()
    }
}

/// Normalized point
///
/// Point that satisfies [`Ciphersuite::is_normalized`].
#[derive(Debug, Clone, Copy)]
pub struct NormalizedPoint<C: Ciphersuite>(Point<C::Curve>);

impl<C: Ciphersuite> NormalizedPoint<C> {
    /// Serialzies the normalized point in a space-efficient manner
    ///
    /// Alias to [`Ciphersuite::serialize_normalized_point`]
    pub fn to_bytes(&self) -> C::NormalizedPointBytes {
        C::serialize_normalized_point(self)
    }
}

impl<C: Ciphersuite> TryFrom<Point<C::Curve>> for NormalizedPoint<C> {
    type Error = NormalizedPoint<C>;

    /// Normalizes the point
    ///
    /// Returns `Ok(point)` is point is already normalized, or `Err(-point)` otherwise.
    fn try_from(point: Point<C::Curve>) -> Result<Self, Self> {
        if C::is_normalized(&point) {
            Ok(Self(point))
        } else {
            debug_assert!(C::is_normalized(&(-point)));
            Err(Self(-point))
        }
    }
}
impl<C: Ciphersuite> core::ops::Deref for NormalizedPoint<C> {
    type Target = Point<C::Curve>;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<C: Ciphersuite> core::cmp::PartialEq for NormalizedPoint<C> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}
impl<C: Ciphersuite> core::cmp::Eq for NormalizedPoint<C> {}

#[cfg(feature = "serde")]
impl<C: Ciphersuite> serde::Serialize for NormalizedPoint<C> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        // Normalized point is serialized as a regular point - we do not take advantage
        // of shorter form in serde traits to keep impl simpler
        (**self).serialize(serializer)
    }
}
#[cfg(feature = "serde")]
impl<'de, C: Ciphersuite> serde::Deserialize<'de> for NormalizedPoint<C> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let point = Point::<C::Curve>::deserialize(deserializer)?;
        NormalizedPoint::<C>::try_from(point)
            .map_err(|_| <D::Error as serde::de::Error>::custom("point isn't normalized"))
    }
}

/// Normalizes the key share
///
/// Some Schnorr signing schemes require public key to be [normalized](Ciphersuite::is_normalized).
/// Generally, DKG protocols output arbitrary public keys which are not necessarily normalized. If
/// you want to use this key in the Schnorr scheme that requires public keys to be normalized, each
/// key share needs to be normalized using this function.
///
/// ## Error
/// Returns an error if output key share is inconsistent. That should never happen in practice. If
/// it happened, it's probably a bug.
pub fn normalize_key_share<C: Ciphersuite>(
    key_share: crate::key_share::KeyShare<C::Curve>,
) -> Result<crate::key_share::KeyShare<C::Curve>, crate::key_share::InvalidKeyShare> {
    use crate::key_share::Validate;

    let Err(new_pk) = NormalizedPoint::<C>::try_from(key_share.shared_public_key) else {
        // Public key is already normalized
        return Ok(key_share);
    };
    let key_share = key_share.into_inner();

    // PK is negated. Now we need to negate the key share, and each public key share
    let new_sk = SecretScalar::new(&mut -(key_share.x.as_ref()));
    let public_shares = key_share
        .public_shares
        .iter()
        .map(|p| -p)
        .collect::<Vec<_>>();

    crate::key_share::DirtyKeyShare {
        i: key_share.i,
        key_info: crate::key_share::DirtyKeyInfo {
            shared_public_key: *new_pk,
            public_shares,
            ..key_share.key_info
        },
        x: new_sk,
    }
    .validate()
    .map_err(|e| e.into_error())
}
