mod interactive;
mod test_vectors;

#[generic_tests::define(attrs(test_case::case))]
mod generic {
    use givre::{ciphersuite::NormalizedPoint, Ciphersuite};
    use givre_tests::ExternalVerifier;
    use rand::{seq::SliceRandom, Rng, RngCore};

    #[test_case::case(Some(2), 3; "t2n3")]
    #[test_case::case(Some(3), 3; "t3n3")]
    #[test_case::case(None, 3; "n3")]
    #[test_case::case(Some(3), 5; "t3n5")]
    #[test_case::case(Some(5), 5; "t5n5")]
    #[test_case::case(None, 5; "n5")]
    fn sign<C: Ciphersuite + ExternalVerifier>(t: Option<u16>, n: u16) {
        let mut rng = rand_dev::DevRng::new();

        // Emulate keygen via trusted dealer
        let key_shares = givre::trusted_dealer::builder::<C::Curve>(n)
            .set_threshold(t)
            .generate_shares(&mut rng)
            .unwrap();
        let key_shares = key_shares
            .into_iter()
            .map(givre::ciphersuite::normalize_key_share::<C>)
            .collect::<Result<Vec<_>, _>>()
            .expect("normalize key shares");
        let key_info: &givre::key_share::KeyInfo<_> = key_shares[0].as_ref();
        let pk = NormalizedPoint::<C>::try_from(key_info.shared_public_key)
            .expect("public key is not normalized");

        // List of indexes of signers who co-hold the key
        let key_holders = (0..n).collect::<Vec<_>>();
        let t = t.unwrap_or(n);

        // Choose `t` signers to perform signing
        let signers = key_holders
            .choose_multiple(&mut rng, t.into())
            .copied()
            .collect::<Vec<_>>();

        // Round 1. Each signer commits
        let mut secret_nonces = vec![];
        let mut public_commitments = vec![];

        for &j in &signers {
            let (nonces, commitments) =
                givre::signing::round1::commit::<C>(&mut rng, &key_shares[usize::from(j)]);

            secret_nonces.push(nonces);
            public_commitments.push((j, commitments));
        }

        // Round 2. Each signer signs a message
        let message_len = C::REQUIRED_MESSAGE_SIZE.unwrap_or_else(|| rng.gen_range(20..=100));
        let mut message = vec![0u8; message_len];
        rng.fill_bytes(&mut message);

        let partial_sigs = public_commitments
            .iter()
            .zip(secret_nonces)
            .map(|(&(j, comm), secret_nonces)| {
                let sig_share = givre::signing::round2::sign::<C>(
                    &key_shares[usize::from(j)],
                    secret_nonces,
                    &message,
                    &public_commitments,
                )?;
                Ok::<_, givre::signing::round2::SigningError>((j, comm, sig_share))
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("signing failed");

        // Round 3. Aggregate sig shares
        let sig = givre::signing::aggregate::aggregate::<C>(&key_info, &partial_sigs, &message)
            .expect("aggregation failed");

        sig.verify(&pk, &message).expect("invalid signature");
        C::verify_sig(&pk, &sig, &message).expect("external verifier: invalid signature")
    }

    #[instantiate_tests(<givre::ciphersuite::Bitcoin>)]
    mod bitcoin {}
    #[instantiate_tests(<givre::ciphersuite::Secp256k1>)]
    mod secp256k1 {}
    #[instantiate_tests(<givre::ciphersuite::Ed25519>)]
    mod ed25519 {}
}
