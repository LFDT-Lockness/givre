//! # Threshold Schnorr implementation based on [FROST IETF Draft][draft]
//!
//! [FROST][draft] is state of art protocol for Threshold Schnorr Signatures that supports 1-round signing (requires
//! signers to [commit nonces](signing::round1) ahead of time), and identifiable abort.
//!
//! This crate provides:
//! * Distributed Key Generation (DKG) \
//!   FROST does not define DKG protocol to be used. We simply re-export DKG based on [CGGMP21] implementation
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
//! The crate is wasm and no_std friendly.
//!
//! # How to use the library
//!
//! ## Distributed Key Generation (DKG)
//! First of all, you need to generate a key. For that purpose, you can use any secure
//! (preferrably, UC-secure) DKG protocol. FROST IETF Draft does not define any DKG
//! protocol or requirements it needs to meet, so the choice is up to you. This library
//! re-exports CGGMP21 DKG from [`cggmp21-keygen`] crate when `cggmp21-keygen` feature
//! is enabled which is proven to be UC-secure and should be a reasonable default.
//!
//! CGGMP21 DKG is an interactive protocol built on [`round_based`] framework. In order
//! to carry it out, you need to define the transport layer (i.e. how the signers can
//! communicate with each other). It's simply a pair of stream and sink:
//!
//! ```rust,ignore
//! let incoming: impl Stream<Item = Result<Incoming<Msg>>>;
//! let outgoing: impl Sink<Outgoing<Msg>>;
//! ```
//!
//! where:
//! * `Msg` is a protocol message (e.g., [`keygen::msg::threshold::Msg`])
//! * [`round_based::Incoming`] and [`round_based::Outgoing`] wrap `Msg` and provide additional data (e.g., sender/recepient)
//! * [`futures::Stream`] and [`futures::Sink`] are well-known async primitives.
//!
//! [`futures::Stream`]: https://docs.rs/futures/latest/futures/stream/trait.Stream.html
//! [`futures::sink`]: https://docs.rs/futures/latest/futures/sink/trait.Sink.html
//!
//! Transport layer implementation needs to meet requirements:
//! * All messages must be authenticated \
//!   Whenever one party receives a message from another, the receiver should cryptographically
//!   verify that the message comes from the claimed sender.
//! * All p2p messages must be encrypted \
//!   Only the designated recipient should be able to read the message
//!
//! Then, construct an [MpcParty](round_based::MpcParty):
//! ```rust
//! # type Msg = givre::keygen::msg::threshold::Msg<givre::generic_ec::curves::Secp256k1, givre::keygen::security_level::SecurityLevel128, sha2::Sha256>;
//! # let incoming = futures::stream::pending::<Result<round_based::Incoming<Msg>, std::convert::Infallible>>();
//! # let outgoing = futures::sink::drain::<round_based::Outgoing<Msg>>();
//! let delivery = (incoming, outgoing);
//! let party = round_based::MpcParty::connected(delivery);
//! ```
//!
//! Now, you can finally execute the DKG protocol. The protocol involves all signers
//! who will co-share a key. All signers need to agree on some basic parameters including
//! the participants’ indices, the execution ID, and the threshold value (i.e., t).
//! ```rust,no_run
//! use givre::ciphersuite::{Ciphersuite, Secp256k1};
//!
//! # async fn doc() -> Result<(), givre::keygen::KeygenError> {
//! # type Msg = givre::keygen::msg::threshold::Msg<<Secp256k1 as Ciphersuite>::Curve, givre::keygen::security_level::SecurityLevel128, sha2::Sha256>;
//! # let incoming = futures::stream::pending::<Result<round_based::Incoming<Msg>, std::convert::Infallible>>();
//! # let outgoing = futures::sink::drain::<round_based::Outgoing<Msg>>();
//! # let delivery = (incoming, outgoing);
//! # let party = round_based::MpcParty::connected(delivery);
//! #
//! # use rand_core::OsRng;
//! #
//! let eid = givre::keygen::ExecutionId::new(b"execution id, unique per protocol execution");
//! let i = /* signer index (0 <= i < n) */
//! # 0;
//! let n = /* number of signers taking part in key generation */
//! # 3;
//! let t = /* threshold */
//! # 2;
//!
//! let key_share = givre::keygen::<<Secp256k1 as Ciphersuite>::Curve>(eid, i, n)
//!     .set_threshold(t)
//!     .start(&mut OsRng, party)
//!     .await?;
//! # Ok(()) }
//! ```
//!
//! ## Signing
//! FROST signing can be carried out either interactively with the help of [`round_based`]
//! framework, or manually.
//!
//! ### Manual Signing
//! In the manual signing, as the name suggests, you manually construct all messages
//! and drive the protocol. It gives you better control over protocol execution and
//! you can benefit from better performance (e.g. by having 1 round signing). However,
//! it also gives a greater chance of misusing the protocol and violating security.
//! When opting for manual signing, make sure you're familiar with the [FROST IETF Draft][draft].
//! Refer to [mod@signing] module docs for the instructions.
//!
//! ### Interactive Signing (requires `full-signing` feature)
//! Interactive Signing has more user-friendly interface and harder-to-misuse design.
//! It works on top of [`round_based`] framework similarly to DKG described above.
//! As before, you need to define a secure transport layer and construct [MpcParty](round_based::MpcParty).
//! Then, you need to assign each signer a unique index, in range from 0 to t-1. The
//! signers also need to know which index each of them occupied at the time of keygen.
//!
//! ```rust,no_run
//! use givre::ciphersuite::Secp256k1;
//!
//! # async fn doc() -> Result<(), givre::signing::full_signing::FullSigningError> {
//! # type Msg = givre::signing::full_signing::Msg<<Secp256k1 as givre::Ciphersuite>::Curve>;
//! # let incoming = futures::stream::pending::<Result<round_based::Incoming<Msg>, std::convert::Infallible>>();
//! # let outgoing = futures::sink::drain::<round_based::Outgoing<Msg>>();
//! # let delivery = (incoming, outgoing);
//! # let party = round_based::MpcParty::connected(delivery);
//! #
//! # use rand_core::OsRng;
//! # const MIN_SIGNERS: usize = 3;
//! #
//! #
//! let i = /* signer index (0 <= i < min_signers) */
//! # 0;
//! let parties_indexes_at_keygen: [u16; MIN_SIGNERS] =
//!     /* parties_indexes_at_keygen[i] is the index the i-th party had at keygen */
//! # [0, 1, 2];
//! let key_share = /* key share */
//! # {let s: givre::KeyShare<<Secp256k1 as givre::Ciphersuite>::Curve> = unimplemented!(); s};
//!
//! let data_to_sign = b"data to be signed";
//!
//! let signature = givre::signing::<Secp256k1>(i, &key_share, &parties_indexes_at_keygen, data_to_sign)
//!     .sign(&mut OsRng, party)
//!     .await?;
//! # Ok(()) }
//! ```
//! ## Signer indices
//! We use indices to uniquely refer to particular signers sharing a key. Each
//! index `i` is an unsigned integer `u16` with `0 ≤ i < n` where `n` is the
//! total number of participants in the protocol.
//!
//! All signers should have the same view about each others’ indices. For instance,
//! if Signer A holds index 2, then all other signers must agree that i=2 corresponds
//! to Signer A.
//!
//! Assuming some sort of PKI (which would anyway likely be used to ensure secure
//! communication, as described above), each signer has a public key that uniquely
//! identifies that signer. It is then possible to assign unique indices to the signers
//! by lexicographically sorting the signers’ public keys, and letting the index of a
//! signer be the position of that signer’s public key in the sorted list.
//!
//! # Webassembly and `no_std` support
//! This crate is compatible with `wasm32-unknown-unknown` target and `no_std` unless
//! `cggmp21-keygen`, `full-signing`, or `std` features are enabled. Other WASM targets
//! might be supported even if these features are on.
//!
//! [CGGMP21]: https://github.com/dfns/cggmp21
//! [draft]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html

#![forbid(unsafe_code, unused_crate_dependencies)]
#![deny(clippy::expect_used, clippy::unwrap_used, clippy::panic)]
#![deny(missing_docs)]
#![allow(clippy::type_complexity)]
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![no_std]

#[cfg(feature = "std")]
extern crate std;

extern crate alloc;

pub use generic_ec;
#[cfg(feature = "full-signing")]
pub use round_based;

pub mod ciphersuite;
pub mod signing;

#[cfg(test)]
mod _unused_deps {
    // `futures` causes false-positive because it's only used in the docs examples
    use futures as _;
}

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
///     .sign(&mut rand_core::OsRng, party)
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
