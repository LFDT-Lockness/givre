//! FROST Threshold Signing Protocol
//!
//! This crate provides two options how the protocol can be carried out: manually or interactively.
//! ## Manually
//! You can manually carry out each phase of the protocol by using [round1], [round2], [aggregate] modules.
//! This gives greater flexibility, but you must be carefull not to do anything that could harm security.
//!
//! Manual signing is done as described below. We assume presence of Coordinator, it can be either some entity
//! in the system, or it could be implemented as some sort of consensus protocol between the signers.
//! 1. Each signer commits nonces via [round1::commit] \
//!    Inputs to this phase: source of cryptographic randomness and source of additional entropy (like key share). \
//!    Message to be signed doesn't need to be known at this point yet. \
//!    Outputs:
//!    * [round1::SecretNonces] that need to be kept secret
//!    * [round1::PublicCommitments] that need to be sent to Coordinator
//! 2. Coordinator receives a request to sign a message `msg`. It chooses a set of signer (of size `min_signers`) who
//!    will carry out signing. For each signer, it chooses a commitment previously sent by the signer. It forwards
//!    signing request to each signer along with list of commitments.
//! 3. Signer receives a signing request. Signer retrieves [round1::SecretNonces] corresponding to the commitments
//!    chosen by the Coordinator. Signer must delete retrieved secret nonces and make sure they can never be used
//!    again.
//! 4. Each signer signs a message via [round2::sign], and sends the resulting [round2::SigShare] to Coorinator.
//! 5. Coordinator receives [round2::SigShare] from each Signer, and aggregates them via [aggregate::aggregate]
//!    into a regular [aggregate::Signature].
//!
//! ## Interactivelly
//! When `full-signing` feature is enabled, you can use [`signing`](crate::signing()) function to carry out
//! full signing protocol based on [`round_based`] framework. This provides the best security, although
//! you lose flexibility, for instance, to commit nonces before message to be signed is known.

pub mod aggregate;
#[cfg(feature = "full-signing")]
pub mod full_signing;
pub mod round1;
pub mod round2;
mod utils;
