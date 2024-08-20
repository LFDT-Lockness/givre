//! Interactive Signing

use alloc::{boxed::Box, vec::Vec};
use core::fmt;

use generic_ec::Curve;
use rand_core::{CryptoRng, RngCore};
use round_based::{
    rounds_router::{simple_store::RoundInput, RoundsRouter},
    Delivery, SinkExt,
};

use crate::{
    key_share::{KeyInfo, KeyShare},
    Ciphersuite, SignerIndex,
};

use super::{aggregate::Signature, round1::PublicCommitments, round2::SigShare, utils};

/// Message of FROST Signing Protocol
#[derive(Debug, Clone, Copy, round_based::ProtocolMessage)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(bound = "")
)]
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

    hd_additive_shift: Option<generic_ec::Scalar<C::Curve>>,
    taproot_merkle_root: Option<Option<[u8; 32]>>,
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
            hd_additive_shift: None,
            taproot_merkle_root: None,
        }
    }

    /// Specifies HD derivation path
    ///
    /// If called twice, the second call overwrites the first.
    ///
    /// Returns error if the key doesn't support HD derivation, or if the path is invalid
    #[cfg(feature = "hd-wallets")]
    pub fn set_derivation_path<Index>(
        mut self,
        path: impl IntoIterator<Item = Index>,
    ) -> Result<Self, crate::key_share::HdError<<slip_10::NonHardenedIndex as TryFrom<Index>>::Error>>
    where
        slip_10::NonHardenedIndex: TryFrom<Index>,
    {
        use crate::key_share::HdError;

        let public_key = self
            .key_share
            .extended_public_key()
            .ok_or(HdError::DisabledHd)?;
        let additive_shift =
            utils::derive_additive_shift(public_key, path).map_err(HdError::InvalidPath)?;
        self.hd_additive_shift = Some(additive_shift);
        Ok(self)
    }

    /// Tweaks the key with specified merkle root following [BIP-341]
    ///
    /// Note that the taproot spec requires that any key must be tweaked. By default, if this
    /// method is not called for taproot-enabled ciphersuite, then an empty merkle root
    /// is assumed.
    ///
    /// The method returns an error if the ciphersuite doesn't support taproot, i.e. if
    /// [`Ciphersuite::IS_TAPROOT`] is `false`
    ///
    /// [BIP-341]: https://github.com/bitcoin/bips/blob/master/bip-0341.mediawiki
    #[cfg(feature = "taproot")]
    pub fn set_taproot_tweak(
        mut self,
        merkle_root: Option<[u8; 32]>,
    ) -> Result<Self, FullSigningError> {
        if !C::IS_TAPROOT {
            return Err(Reason::NonTaprootCiphersuite.into());
        }

        self.taproot_merkle_root = Some(merkle_root);
        Ok(self)
    }

    /// Issues signature share
    ///
    /// Signer will output a signature share. It'll be more efficient than [generating a full signature](Self::sign),
    /// but it requires you to collect all sig shares in one place and [aggregate](crate::signing::aggregate::aggregate)
    /// them.
    pub async fn issue_sig_share<M, R>(
        self,
        rng: &mut R,
        party: M,
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
            self.hd_additive_shift,
            self.taproot_merkle_root,
            true,
        )
        .await?
        {
            SigningOutput::SigShare(out) => Ok(out),
            _ => Err(Bug::UnexpectedOutput.into()),
        }
    }

    /// Executes Interactive Signing protocol
    pub async fn sign<M, R>(self, rng: &mut R, party: M) -> Result<Signature<C>, FullSigningError>
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
            self.hd_additive_shift,
            self.taproot_merkle_root,
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
    hd_additive_shift: Option<generic_ec::Scalar<C::Curve>>,
    taproot_merkle_root: Option<Option<[u8; 32]>>,
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

    let mut options =
        crate::signing::round2::SigningOptions::<C>::new(key_share, nonces, msg, &signers_list);
    #[cfg(feature = "hd-wallets")]
    if let Some(additive_shift) = hd_additive_shift {
        options = options.dangerous_set_hd_additive_shift(additive_shift);
    }
    if cfg!(not(feature = "hd-wallets")) && hd_additive_shift.is_some() {
        return Err(Bug::AdditiveShiftWithoutHdFeature.into());
    }
    #[cfg(feature = "taproot")]
    if let Some(root) = taproot_merkle_root {
        options = options
            .set_taproot_tweak(root)
            .map_err(Bug::SetTaprootTweakSign)?;
    }
    if cfg!(not(feature = "taproot")) && taproot_merkle_root.is_some() {
        return Err(Bug::TaprootSpecifiedButDisabled.into());
    }
    let sig_share = options.sign().map_err(Reason::Sign)?;

    if output_sig_share {
        return Ok(SigningOutput::SigShare(sig_share));
    }

    outgoing
        .send(round_based::Outgoing::broadcast(Msg::Round2(sig_share)))
        .await
        .map_err(IoError::send)?;

    // Aggregate signature
    let sig_shares = rounds.complete(round2).await.map_err(IoError::recv)?;

    let signers_list = signers_list
        .into_iter()
        .zip(sig_shares.iter_including_me(&sig_share))
        .map(|((j, comm), &sig_share)| (j, comm, sig_share))
        .collect::<Vec<_>>();

    let key_info: &KeyInfo<_> = key_share.as_ref();
    let mut options =
        crate::signing::aggregate::AggregateOptions::new(key_info, &signers_list, msg);
    #[cfg(feature = "hd-wallets")]
    if let Some(additive_shift) = hd_additive_shift {
        options = options.dangerous_set_hd_additive_shift(additive_shift);
    }
    #[cfg(feature = "taproot")]
    if let Some(root) = taproot_merkle_root {
        options = options
            .set_taproot_tweak(root)
            .map_err(Bug::SetTaprootTweakAggregate)?;
    }
    let sig = options.aggregate().map_err(Reason::Aggregate)?;

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
    NonTaprootCiphersuite,
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
    Send(Box<dyn crate::error::StdError + Send + Sync>),
    Recv(Box<dyn crate::error::StdError + Send + Sync>),
}

impl IoError {
    fn send(err: impl crate::error::StdError + Send + Sync + 'static) -> Self {
        Self::Send(Box::new(err))
    }
    fn recv(err: impl crate::error::StdError + Send + Sync + 'static) -> Self {
        Self::Recv(Box::new(err))
    }
}

#[derive(Debug)]
enum Bug {
    UnexpectedOutput,
    AdditiveShiftWithoutHdFeature,
    SetTaprootTweakSign(crate::signing::round2::SigningError),
    SetTaprootTweakAggregate(crate::signing::aggregate::AggregateError),
    TaprootSpecifiedButDisabled,
}

impl fmt::Display for FullSigningError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Reason::NonTaprootCiphersuite => f.write_str("ciphersuite doesn't support taproot"),
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
            Bug::AdditiveShiftWithoutHdFeature => {
                f.write_str("additive shift is specified, but hd wallets are disabled")
            }
            Bug::SetTaprootTweakSign(_) => f.write_str("set taproot tweak failed (sign)"),
            Bug::SetTaprootTweakAggregate(_) => f.write_str("set taproot tweak failed (aggregate)"),
            Bug::TaprootSpecifiedButDisabled => {
                f.write_str("taproot merkle root is specified, but taproot feature is not enabled")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FullSigningError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match &self.0 {
            Reason::NonTaprootCiphersuite
            | Reason::NOverflowsU16
            | Reason::INotInRange
            | Reason::UnexpectedNumberOfSigners => None,
            Reason::IoError(IoError::Send(err)) | Reason::IoError(IoError::Recv(err)) => {
                Some(&**err)
            }
            Reason::Sign(err) => Some(err),
            Reason::Aggregate(err) => Some(err),
            Reason::Bug(err) => Some(err),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Bug {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Bug::UnexpectedOutput => None,
            Bug::AdditiveShiftWithoutHdFeature => None,
            Bug::SetTaprootTweakSign(err) => Some(err),
            Bug::SetTaprootTweakAggregate(err) => Some(err),
            Bug::TaprootSpecifiedButDisabled => None,
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
