use anyhow::{Context, Result};
use givre::{
    generic_ec::{NonZero, Point},
    signing::aggregate::Signature,
    Ciphersuite,
};

pub trait ExternalVerifier: Ciphersuite {
    /// Although Schnorr scheme can sign messages of arbitrary size, external verifier may require that
    /// the message needs to be an output of a hash function with fixed size
    const REQUIRED_MESSAGE_SIZE: Option<usize> = None;

    /// Indicates whether external lib supports HD derivation
    const SUPPORTS_HD: bool = false;

    /// Verifies signature using external library
    ///
    /// Takes arguments:
    /// * Public key `pk` (without any modifications like HD derivations)
    /// * HD derivation path. Empty path disables derivation.
    /// * Taproot merkle root. `None` disables tweaking.
    /// * Signature
    /// * Message to verify
    ///
    /// Returns an error if:
    /// * Signature is invalid
    /// * HD derivation is provided but not supported by external library
    /// * Taproot specified but not supported by external library
    /// * Taproot is not specified, but required by external library
    fn verify_sig(
        pk: &NonZero<Point<Self::Curve>>,
        chain_code: Option<[u8; 32]>,
        hd_derivation_path: &[u32],
        taproot_merkle_root: Option<Option<[u8; 32]>>,
        sig: &Signature<Self>,
        msg: &[u8],
    ) -> Result<()>;
}

#[derive(Debug)]
pub struct InvalidSignature;

impl ExternalVerifier for givre::ciphersuite::Ed25519 {
    fn verify_sig(
        pk: &NonZero<Point<Self::Curve>>,
        _chain_code: Option<[u8; 32]>,
        hd_derivation_path: &[u32],
        taproot_merkle_root: Option<Option<[u8; 32]>>,
        sig: &Signature<Self>,
        msg: &[u8],
    ) -> Result<()> {
        if !hd_derivation_path.is_empty() {
            anyhow::bail!("HD derivation is not supported by ed25519_dalek")
        }
        if taproot_merkle_root.is_some() {
            anyhow::bail!("taproot is not compatible with EdDSA")
        }

        let pk = ed25519::VerifyingKey::from_bytes(
            &Self::serialize_point(pk)
                .as_bytes()
                .try_into()
                .expect("wrong size of pk"),
        )
        .expect("invalid pk");
        let mut sig_bytes = [0u8; 64];
        sig_bytes[..32].copy_from_slice(&Self::serialize_point(&sig.r));
        sig_bytes[32..].copy_from_slice(&Self::serialize_scalar(&sig.z));
        let sig = ed25519::Signature::from_bytes(&sig_bytes);

        pk.verify_strict(msg, &sig).context("invalid signature")
    }
}

impl ExternalVerifier for givre::ciphersuite::Secp256k1 {
    fn verify_sig(
        _pk: &NonZero<Point<Self::Curve>>,
        _chain_code: Option<[u8; 32]>,
        hd_derivation_path: &[u32],
        taproot_merkle_root: Option<Option<[u8; 32]>>,
        _sig: &Signature<Self>,
        _msg: &[u8],
    ) -> Result<()> {
        if !hd_derivation_path.is_empty() {
            anyhow::bail!("HD derivation is not supported by ed25519_dalek")
        }
        if taproot_merkle_root.is_some() {
            anyhow::bail!("taproot is not compatible with EdDSA")
        }

        // No external verifier for secp256k1 ciphersuite
        Ok(())
    }
}

impl ExternalVerifier for givre::ciphersuite::Bitcoin {
    const REQUIRED_MESSAGE_SIZE: Option<usize> = Some(32);

    fn verify_sig(
        pk: &NonZero<Point<Self::Curve>>,
        chain_code: Option<[u8; 32]>,
        hd_derivation_path: &[u32],
        taproot_merkle_root: Option<Option<[u8; 32]>>,
        sig: &Signature<Self>,
        msg: &[u8],
    ) -> Result<()> {
        let pk =
            bitcoin::secp256k1::PublicKey::from_slice(&pk.to_bytes(true)).context("public key")?;

        let pk: bitcoin::key::UntweakedPublicKey = if !hd_derivation_path.is_empty() {
            let chain_code = chain_code.context("chain code is missing")?;
            let mut xpub = bitcoin::bip32::Xpub {
                network: bitcoin::NetworkKind::Main,
                depth: 0,
                parent_fingerprint: Default::default(),
                child_number: bitcoin::bip32::ChildNumber::from_normal_idx(0)
                    .context("child idx")?,
                public_key: pk,
                chain_code: bitcoin::bip32::ChainCode::from(chain_code),
            };

            for &child_index in hd_derivation_path {
                let child_index = bitcoin::bip32::ChildNumber::from_normal_idx(child_index)
                    .context("only non-hardened derivation is supported")?;
                xpub = xpub
                    .ckd_pub(&secp256k1::SECP256K1, child_index)
                    .context("child derivation")?;
            }

            xpub.to_x_only_pub()
        } else {
            pk.x_only_public_key().0
        };

        let taproot_merkle_root = taproot_merkle_root
            .context("taproot merkle root is mandatory")?
            .map(bitcoin::TapNodeHash::assume_hidden);

        let (pk, _) =
            bitcoin::key::TapTweak::tap_tweak(pk, &secp256k1::SECP256K1, taproot_merkle_root);

        let mut signature = [0u8; 64];
        assert_eq!(signature.len(), Signature::<Self>::serialized_len());
        sig.write_to_slice(&mut signature);
        let signature = secp256k1::schnorr::Signature::from_slice(&signature)?;

        let msg = secp256k1::Message::from_digest_slice(msg)?;

        signature
            .verify(&msg, &pk.to_inner())
            .context("invalid signature")
    }
}

/// Generates a random merkle root for taproot derivation
///
/// With 1/2 probability it outputs `None` (corresponds to empty merkle root in bip341),
/// otherwise it generates a random merkle root and returns `Some(root)`
pub fn random_taproot_merkle_root(rng: &mut impl rand::Rng) -> Option<[u8; 32]> {
    if rng.gen() {
        None
    } else {
        Some(rng.gen())
    }
}

/// Generates a random non-hardened HD derivation path which has somewhere
/// between 0 to 3 indexes
pub fn random_hd_path(rng: &mut impl rand::Rng) -> Vec<u32> {
    let len = rng.gen_range(0..=3);
    std::iter::repeat_with(|| rng.gen_range(0..givre::hd_wallet::H))
        .take(len)
        .collect()
}
