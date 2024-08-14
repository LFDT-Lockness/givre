mod interactive;
mod test_vectors;

#[generic_tests::define(attrs(test_case::case, test))]
mod generic {
    use anyhow::Context;
    use givre::Ciphersuite;
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
        let key_info: &givre::key_share::KeyInfo<_> = key_shares[0].as_ref();
        let pk = key_info.shared_public_key;

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

        // message to be signed
        let message_len = C::REQUIRED_MESSAGE_SIZE.unwrap_or_else(|| rng.gen_range(20..=100));
        let mut message = vec![0u8; message_len];
        rng.fill_bytes(&mut message);
        println!("message to sign: {}", hex::encode(&message));

        // HD derivation path
        let derivation_path = if C::SUPPORTS_HD {
            givre_tests::random_hd_path(&mut rng)
        } else {
            vec![]
        };
        println!("HD path: {derivation_path:?}");

        // Taproot merkle root
        let taproot_merkle_root = if C::IS_TAPROOT {
            Some(givre_tests::random_taproot_merkle_root(&mut rng))
        } else {
            None
        };
        println!(
            "Taproot merkle root: {:?}",
            taproot_merkle_root.map(|r| r.map(hex::encode))
        );

        let partial_sigs = public_commitments
            .iter()
            .zip(secret_nonces)
            .map(|(&(j, comm), secret_nonces)| {
                let mut options = givre::signing::round2::SigningOptions::<C>::new(
                    &key_shares[usize::from(j)],
                    secret_nonces,
                    &message,
                    &public_commitments,
                );
                if !derivation_path.is_empty() {
                    options = options
                        .set_derivation_path(derivation_path.iter().copied())
                        .context("set derivation path")?;
                }
                if let Some(root) = taproot_merkle_root {
                    options = options
                        .set_taproot_tweak(root)
                        .context("set taproot tweak")?;
                }
                let sig_share = options.sign().context("sign")?;
                Ok::<_, anyhow::Error>((j, comm, sig_share))
            })
            .collect::<Result<Vec<_>, _>>()
            .expect("signing failed");

        // Round 3. Aggregate sig shares
        let mut options = givre::signing::aggregate::AggregateOptions::<C>::new(
            key_info,
            &partial_sigs,
            &message,
        );
        if !derivation_path.is_empty() {
            options = options
                .set_derivation_path(derivation_path.iter().copied())
                .expect("set derivation path");
        }
        if let Some(root) = taproot_merkle_root {
            options = options.set_taproot_tweak(root).expect("set taproot tweak");
        }
        let sig = options.aggregate().expect("aggregate");

        // Verify signature using external library
        C::verify_sig(
            &pk,
            key_shares[0].chain_code,
            &derivation_path,
            taproot_merkle_root,
            &sig,
            &message,
        )
        .expect("external verifier: invalid signature")
    }

    #[test]
    fn point_and_scalar_sizes_are_correct<C: Ciphersuite>() {
        use givre::generic_ec::{Point, Scalar};

        let serialized_scalar = C::serialize_scalar(&Scalar::<C::Curve>::one());
        assert_eq!(serialized_scalar.as_ref().len(), C::SCALAR_SIZE);

        let normalized_point = C::normalize_point(Point::<C::Curve>::zero());
        let serialized_point = C::serialize_normalized_point(&normalized_point);
        assert_eq!(serialized_point.as_ref().len(), C::NORMALIZED_POINT_SIZE);
    }

    #[test]
    fn serialize_deserialize_sig<C: Ciphersuite>() {
        use givre::generic_ec::{Point, Scalar};

        let mut rng = rand_dev::DevRng::new();

        let r = C::normalize_point(Point::<C::Curve>::generator() * Scalar::random(&mut rng));
        let z = Scalar::random(&mut rng);

        let sig = givre::signing::aggregate::Signature::<C> { r, z };

        let sig_len = givre::signing::aggregate::Signature::<C>::serialized_len();
        let mut sig_bytes = vec![0u8; sig_len];

        sig.write_to_slice(&mut sig_bytes);

        let parsed_sig = givre::signing::aggregate::Signature::read_from_slice(&sig_bytes).unwrap();
        assert_eq!(parsed_sig.r, r);
        assert_eq!(parsed_sig.z, z);
    }

    #[instantiate_tests(<givre::ciphersuite::Bitcoin>)]
    mod bitcoin {}
    #[instantiate_tests(<givre::ciphersuite::Secp256k1>)]
    mod secp256k1 {}
    #[instantiate_tests(<givre::ciphersuite::Ed25519>)]
    mod ed25519 {}
}
