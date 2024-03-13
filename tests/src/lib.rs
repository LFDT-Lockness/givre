use givre::{
    ciphersuite::NormalizedPoint,
    generic_ec::{NonZero, Point},
    signing::aggregate::Signature,
    Ciphersuite,
};

pub trait ExternalVerifier: Ciphersuite {
    /// Although Schnorr scheme can sign messages of arbitrary size, external verifier may require that
    /// message to be signed to be hashed
    const REQUIRED_MESSAGE_SIZE: Option<usize> = None;

    type InvalidSig: core::fmt::Debug;

    fn verify_sig(
        pk: &NormalizedPoint<Self, NonZero<Point<Self::Curve>>>,
        sig: &Signature<Self>,
        msg: &[u8],
    ) -> Result<(), Self::InvalidSig>;
}

#[derive(Debug)]
pub struct InvalidSignature;

impl ExternalVerifier for givre::ciphersuite::Ed25519 {
    type InvalidSig = ed25519::SignatureError;

    fn verify_sig(
        pk: &NormalizedPoint<Self, NonZero<Point<Self::Curve>>>,
        sig: &Signature<Self>,
        msg: &[u8],
    ) -> Result<(), ed25519::SignatureError> {
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

        pk.verify_strict(msg, &sig)
    }
}

impl ExternalVerifier for givre::ciphersuite::Secp256k1 {
    type InvalidSig = core::convert::Infallible;

    fn verify_sig(
        _pk: &NormalizedPoint<Self, NonZero<Point<Self::Curve>>>,
        _sig: &Signature<Self>,
        _msg: &[u8],
    ) -> Result<(), Self::InvalidSig> {
        // No external verifier for secp256k1 ciphersuite
        Ok(())
    }
}

impl ExternalVerifier for givre::ciphersuite::Bitcoin {
    const REQUIRED_MESSAGE_SIZE: Option<usize> = Some(32);

    type InvalidSig = secp256k1::Error;

    fn verify_sig(
        pk: &NormalizedPoint<Self, NonZero<Point<Self::Curve>>>,
        sig: &Signature<Self>,
        msg: &[u8],
    ) -> Result<(), Self::InvalidSig> {
        let pk = secp256k1::XOnlyPublicKey::from_slice(pk.to_bytes().as_ref())?;

        let mut signature = [0u8; 64];
        signature[..32].copy_from_slice(sig.r.to_bytes().as_ref());
        signature[32..].copy_from_slice(Self::serialize_scalar(&sig.z).as_ref());

        let signature = secp256k1::schnorr::Signature::from_slice(&signature)?;

        let msg = secp256k1::Message::from_digest_slice(msg)?;

        signature.verify(&msg, &pk)
    }
}
