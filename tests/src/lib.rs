use givre::{generic_ec::Point, signing::aggregate::Signature, Ciphersuite};

pub trait ExternalVerifier: Ciphersuite {
    type InvalidSig: core::fmt::Debug;

    fn verify_sig(
        pk: &Point<Self::Curve>,
        sig: &Signature<Self::Curve>,
        msg: &[u8],
    ) -> Result<(), Self::InvalidSig>;
}

#[derive(Debug)]
pub struct InvalidSignature;

impl ExternalVerifier for givre::ciphersuite::Ed25519 {
    type InvalidSig = ed25519::SignatureError;

    fn verify_sig(
        pk: &Point<Self::Curve>,
        sig: &Signature<Self::Curve>,
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
        _pk: &Point<Self::Curve>,
        _sig: &Signature<Self::Curve>,
        _msg: &[u8],
    ) -> Result<(), Self::InvalidSig> {
        // No external verifier for secp256k1 ciphersuite
        Ok(())
    }
}
