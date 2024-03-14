//! Threshold Schnorr implementation based on [FROST IETF Draft][draft]
//!
//! FROST is state of art protocol for Threshold Schnorr Signatures that supports 1-round signing (requires signers to
//! [commit nonces](signing::round1) ahead of time), and identifiable abort.
//!
//! This crate provides:
//! * Distributed Key Generation (DKG) \
//!   Note that FROST does not define DKG protocol to be used. We simply re-export DKG based on [CGGMP21] implementation
//!   when `cggmp21-keygen` feature is enabled, which is a fairly reasonalbe choice as it's proven to be UC-secure.
//!   Alternatively, you can use any other UC-secure DKG protocol.
//! * FROST Signing \
//!   We provide API for both manual signing execution (for better flexibility and efficiency) and interactive protocol
//!   (for easier usability and fool-proof design), see [mod@signing] module for details.
//! * [Trusted dealer](trusted_dealer) (importing key into TSS)
//! * [reconstruct_secret_key](key_share::reconstruct_secret_key) (exporting key from TSS)
//!
//! This crate doesn't support (currently):
//! * Identifiable abort
//!
//! [CGGMP21]: https://github.com/dfns/cggmp21
//! [draft]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html

#![forbid(unsafe_code, unused_crate_dependencies)]
#![deny(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#![deny(missing_docs)]
#![allow(clippy::type_complexity)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]

pub use generic_ec;
#[cfg(feature = "full-signing")]
pub use round_based;

pub mod ciphersuite;
pub mod signing;

/// Key share
///
/// This module re-exports type definitions from [`key_share`](::key_share) crate.
pub mod key_share {
    #[doc(inline)]
    pub use key_share::{
        CoreKeyShare as KeyShare, DirtyCoreKeyShare as DirtyKeyShare, DirtyKeyInfo,
        InvalidCoreShare as InvalidKeyShare, KeyInfo, Validate, VssSetup,
    };

    #[cfg(feature = "spof")]
    #[doc(inline)]
    pub use key_share::reconstruct_secret_key;
}

/// Distributed Key Generation (DKG) protocol based on CGGMP21 paper
///
/// CGGMP21 DKG protocol is proven to be UC-secure, which means that it can safely be composed with
/// other protocols such as FROST signing. CGGMP21 implementation is audited and heavily used
/// in production, so it should be a reasonably secure DKG implementation.
///
/// This module just re-exports [`cggmp21_keygen`] crate when `cggmp21-keygen` feature is enabled.
#[cfg(feature = "cggmp21-keygen")]
pub mod keygen {
    #[doc(inline)]
    pub use cggmp21_keygen::*;
}

#[cfg(feature = "cggmp21-keygen")]
#[doc(inline)]
pub use cggmp21_keygen::keygen;

/// Trusted dealer
///
/// Trusted dealer can be used to generate key shares in one place. Note
/// that in creates SPOF/T (single point of failure/trust). Trusted
/// dealer is mainly intended to be used in tests, but also could be used
/// to import a key into TSS.
///
/// ## Example
/// Import a key into 3-out-of-5 TSS:
/// ```rust,no_run
/// # use rand_core::OsRng;
/// # let mut rng = OsRng;
/// use givre::generic_ec::{curves::Secp256k1, SecretScalar, NonZero};
///
/// let secret_key_to_be_imported = NonZero::<SecretScalar<Secp256k1>>::random(&mut rng);
///
/// let key_shares = givre::trusted_dealer::builder::<Secp256k1>(5)
///     .set_threshold(Some(3))
///     .set_shared_secret_key(secret_key_to_be_imported)
///     .generate_shares(&mut rng)?;
/// # Ok::<_, key_share::trusted_dealer::TrustedDealerError>(())
/// ```
#[cfg(feature = "spof")]
pub mod trusted_dealer {
    pub use key_share::trusted_dealer::*;
}

pub use self::{
    ciphersuite::Ciphersuite,
    key_share::{KeyInfo, KeyShare},
};

/// Signer index
pub type SignerIndex = u16;

/// Interactive Signing
///
/// Can be used to carry out the full signing protocol in which each signer commits nonces,
/// produces a signature share and, optionally, aggregates all signature shares into the
/// final signature.
///
/// This can be less efficient than doing signing manually, when you can commit nonces before
/// a message to be signed is known, but more secure, as using this function ensures that
/// protocol isn't misused (e.g. that nonce is never resused).
///
/// ## Inputs
/// * Signer index in *signing protocol* $0 \le i < \\text{min\\_signers}$
/// * Signer secret key share
/// * List of signer that participate in the signing, must have exactly threshold amount of signers \
///   `signers[j]` is index which j-th signer occupied at keygen
/// * `msg` to be signed
///
/// ## Example
/// ```rust,no_run
/// use givre::round_based;
/// use givre::ciphersuite::Secp256k1;
/// #
/// # fn retrieve_key_share() -> givre::KeyShare<<Secp256k1 as givre::Ciphersuite>::Curve> { unimplemented!() }
/// # fn join_network<M>() -> (u16, impl round_based::Delivery<M>) {
/// #     (0, (futures::stream::pending::<Result<_, std::convert::Infallible>>(), futures::sink::drain()))
/// # }
/// # async fn __doc() -> Result<(), givre::signing::full_signing::FullSigningError> {
///
/// let key_share = retrieve_key_share();
/// let (i, delivery) = join_network();
/// let signers = [0, 1, 2];
/// let msg = b"Hello, TSS World!";
///
/// let party = round_based::MpcParty::connected(delivery);
/// let sig = givre::signing::<Secp256k1>(i, &key_share, &signers, msg)
///     .sign(party, &mut rand_core::OsRng)
///     .await?;
/// # Ok(()) }
/// ```
#[cfg(feature = "full-signing")]
pub fn signing<'a, C: Ciphersuite>(
    i: SignerIndex,
    key_share: &'a KeyShare<C::Curve>,
    signers: &'a [SignerIndex],
    msg: &'a [u8],
) -> signing::full_signing::SigningBuilder<'a, C> {
    signing::full_signing::SigningBuilder::new(i, key_share, signers, msg)
}
