//! Interactive Signing

use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use futures::SinkExt;
use generic_ec::Curve;
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds_router::{simple_store::RoundInput, RoundsRouter},
    Delivery,
};

use crate::{
    key_share::{KeyInfo, KeyShare},
    Ciphersuite, SignerIndex,
};

use super::{aggregate::Signature, round1::PublicCommitments, round2::SigShare};

/// Message of FROST Signing Protocol
#[derive(Debug, Clone, Copy, round_based::ProtocolMessage)]
pub enum Msg<E: Curve> {
    /// Round 1 message
    Round1(PublicCommitments<E>),
    /// Round 2 message
    Round2(SigShare<E>),
}

/// Builder for FROST Interactive Signing Protocol
pub struct SigningBuilder<'a, C: Ciphersuite> {
    i: SignerIndex,
    key_share: &'a KeyShare<C::Curve>,
    signers: &'a [SignerIndex],
    msg: &'a [u8],
}

impl<'a, C: Ciphersuite> SigningBuilder<'a, C> {
    /// Constructs a signing builder
    ///
    /// It could be easier to use [signing](crate::signing()) function located in the crate root.
    pub fn new(
        i: SignerIndex,
        key_share: &'a KeyShare<C::Curve>,
        signers: &'a [SignerIndex],
        msg: &'a [u8],
    ) -> Self {
        Self {
            i,
            key_share,
            signers,
            msg,
        }
    }

    /// Issues signature share
    ///
    /// Signer will output a signature share. It'll be more efficient than [generating a full signature](Self::sign),
    /// but it requires you to collect all sig shares in one place and [aggreate](crate::signing::aggregate::aggregate)
    /// them.
    pub async fn issue_sig_share<M, R>(
        self,
        party: M,
        rng: &mut R,
    ) -> Result<SigShare<C::Curve>, FullSigningError>
    where
        M: round_based::Mpc<ProtocolMessage = Msg<C::Curve>>,
        R: RngCore + CryptoRng,
    {
        match signing::<C, _>(
            party,
            rng,
            self.i,
            self.key_share,
            self.signers,
            self.msg,
            true,
        )
        .await?
        {
            SigningOutput::SigShare(out) => Ok(out),
            _ => Err(Bug::UnexpectedOutput.into()),
        }
    }

    /// Executes Interactive Signing protocol
    pub async fn sign<M, R>(self, party: M, rng: &mut R) -> Result<Signature<C>, FullSigningError>
    where
        M: round_based::Mpc<ProtocolMessage = Msg<C::Curve>>,
        R: RngCore + CryptoRng,
    {
        match signing::<C, _>(
            party,
            rng,
            self.i,
            self.key_share,
            self.signers,
            self.msg,
            false,
        )
        .await?
        {
            SigningOutput::Signature(out) => Ok(out),
            _ => Err(Bug::UnexpectedOutput.into()),
        }
    }
}

async fn signing<C, M>(
    party: M,
    rng: &mut (impl RngCore + CryptoRng),
    i: SignerIndex,
    key_share: &KeyShare<C::Curve>,
    signers: &[SignerIndex],
    msg: &[u8],
    output_sig_share: bool,
) -> Result<SigningOutput<C>, FullSigningError>
where
    C: Ciphersuite,
    M: round_based::Mpc<ProtocolMessage = Msg<C::Curve>>,
{
    let n = signers
        .len()
        .try_into()
        .map_err(|_| Reason::NOverflowsU16)?;

    if i >= n {
        return Err(Reason::INotInRange.into());
    }
    if key_share.min_signers() != n {
        return Err(Reason::UnexpectedNumberOfSigners.into());
    }

    let round_based::MpcParty { delivery, .. } = party.into_party();
    let (incoming, mut outgoing) = delivery.split();

    let mut rounds = RoundsRouter::<Msg<C::Curve>>::builder();
    let round1 = rounds.add_round(RoundInput::<PublicCommitments<C::Curve>>::broadcast(i, n));
    let round2 = rounds.add_round(RoundInput::<SigShare<C::Curve>>::broadcast(i, n));
    let mut rounds = rounds.listen(incoming);

    // Round 1
    let (nonces, commitments) = crate::signing::round1::commit::<C>(rng, key_share);
    outgoing
        .send(round_based::Outgoing::broadcast(Msg::Round1(commitments)))
        .await
        .map_err(IoError::send)?;

    // Round 2
    let other_commitments = rounds.complete(round1).await.map_err(IoError::recv)?;

    let signers_list = signers
        .iter()
        .zip(other_commitments.iter_including_me(&commitments))
        .map(|(&j, &comm)| (j, comm))
        .collect::<Vec<_>>();

    let sig_share = crate::signing::round2::sign::<C>(key_share, nonces, msg, &signers_list)
        .map_err(Reason::Sign)?;

    if output_sig_share {
        return Ok(SigningOutput::SigShare(sig_share));
    }

    outgoing
        .send(round_based::Outgoing::broadcast(Msg::Round2(sig_share)))
        .await
        .map_err(IoError::send)?;

    // Aggregate sigature
    let sig_shares = rounds.complete(round2).await.map_err(IoError::recv)?;

    let signers_list = signers_list
        .into_iter()
        .zip(sig_shares.iter_including_me(&sig_share))
        .map(|((j, comm), &sig_share)| (j, comm, sig_share))
        .collect::<Vec<_>>();

    let key_info: &KeyInfo<_> = key_share.as_ref();
    let sig = crate::signing::aggregate::aggregate::<C>(key_info, &signers_list, msg)
        .map_err(Reason::Aggregate)?;

    Ok(SigningOutput::Signature(sig))
}

enum SigningOutput<C: Ciphersuite> {
    Signature(Signature<C>),
    SigShare(SigShare<C::Curve>),
}

/// Interactive Signing error
#[derive(Debug)]
pub struct FullSigningError(Reason);

#[derive(Debug)]
enum Reason {
    NOverflowsU16,
    INotInRange,
    UnexpectedNumberOfSigners,
    IoError(IoError),
    Sign(crate::signing::round2::SigningError),
    Aggregate(crate::signing::aggregate::AggregateError),
    Bug(Bug),
}

#[derive(Debug)]
enum IoError {
    Send(Box<dyn std::error::Error + Send + Sync>),
    Recv(Box<dyn std::error::Error + Send + Sync>),
}

impl IoError {
    fn send(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Send(Box::new(err))
    }
    fn recv(err: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self::Recv(Box::new(err))
    }
}

#[derive(Debug)]
enum Bug {
    UnexpectedOutput,
}

impl fmt::Display for FullSigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Reason::NOverflowsU16 => f.write_str("number of signers overflows u16"),
            Reason::INotInRange => f.write_str("signer index not in range (it must be 0 <= i < n)"),
            Reason::UnexpectedNumberOfSigners => f.write_str(
                "unexpected number of signers in the signing: \
                exactly `min_signers` number of signers must \
                participate in signing",
            ),
            Reason::IoError(IoError::Send(_)) => f.write_str("i/o error: send message"),
            Reason::IoError(IoError::Recv(_)) => f.write_str("i/o error: recv message"),
            Reason::Sign(_) => f.write_str("perform signing"),
            Reason::Aggregate(_) => f.write_str("aggregate signature"),
            Reason::Bug(_) => f.write_str("bug occurred"),
        }
    }
}

impl fmt::Display for Bug {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Bug::UnexpectedOutput => f.write_str("unexpected output"),
        }
    }
}

impl std::error::Error for FullSigningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            Reason::NOverflowsU16 | Reason::INotInRange | Reason::UnexpectedNumberOfSigners => None,
            Reason::IoError(IoError::Send(err)) | Reason::IoError(IoError::Recv(err)) => {
                Some(&**err)
            }
            Reason::Sign(err) => Some(err),
            Reason::Aggregate(err) => Some(err),
            Reason::Bug(err) => Some(err),
        }
    }
}

impl std::error::Error for Bug {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Bug::UnexpectedOutput => None,
        }
    }
}

impl From<Reason> for FullSigningError {
    fn from(err: Reason) -> Self {
        Self(err)
    }
}
impl From<Bug> for FullSigningError {
    fn from(err: Bug) -> Self {
        Self(Reason::Bug(err))
    }
}
impl From<IoError> for FullSigningError {
    fn from(err: IoError) -> Self {
        Self(Reason::IoError(err))
    }
}
