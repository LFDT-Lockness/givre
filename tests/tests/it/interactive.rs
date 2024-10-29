#[generic_tests::define(attrs(test_case::case, tokio::test))]
mod generic {
    use std::iter;

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
    #[tokio::test]
    async fn keygen_sign<C: Ciphersuite + ExternalVerifier>(t: Option<u16>, n: u16) {
        let mut rng = rand_dev::DevRng::new();

        // --- Keygen
        let eid: [u8; 32] = rng.gen();
        let eid = givre::keygen::ExecutionId::new(&eid);

        let mut simulation_threshold = round_based::simulation::Simulation::new();
        let mut simulation_nonthreshold = round_based::simulation::Simulation::new();
        let keygen_executions = (0..n)
            .zip(iter::repeat_with(|| {
                (
                    rng.fork(),
                    simulation_threshold.add_party(),
                    simulation_nonthreshold.add_party(),
                )
            }))
            .map(
                move |(j, (mut rng, party_threshold, party_nonthreshold))| async move {
                    if let Some(t) = t {
                        givre::keygen::<C::Curve>(eid, j, n)
                            .set_threshold(t)
                            .hd_wallet(true)
                            .start(&mut rng, party_threshold)
                            .await
                    } else {
                        givre::keygen(eid, j, n)
                            .hd_wallet(true)
                            .start(&mut rng, party_nonthreshold)
                            .await
                    }
                },
            );

        let key_shares: Vec<givre::KeyShare<C::Curve>> =
            futures::future::try_join_all(keygen_executions)
                .await
                .unwrap();
        let pk = key_shares[0].shared_public_key;

        // --- Signing

        // message to be signed
        let msg_len = C::REQUIRED_MESSAGE_SIZE.unwrap_or_else(|| rng.gen_range(20..=100));
        let mut msg = vec![0u8; msg_len];
        rng.fill_bytes(&mut msg);
        let msg = &msg;
        println!("message to sign: {}", hex::encode(msg));

        // HD derivation path
        let derivation_path = givre_tests::random_hd_path(&mut rng);
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

        // Choose `t` signers to do signing
        let t = t.unwrap_or(n);
        let signers = (0..n).collect::<Vec<_>>();
        let signers = signers
            .choose_multiple(&mut rng, t.into())
            .copied()
            .collect::<Vec<_>>();
        let signers = signers.as_slice();

        let mut simulation = round_based::simulation::Simulation::new();
        let signing_executions = (0..t)
            .zip(signers)
            .zip(iter::repeat_with(|| (rng.fork(), simulation.add_party())))
            .map(|((j, &index_at_keygen), (mut rng, party))| {
                let key_share = &key_shares[usize::from(index_at_keygen)];
                let derivation_path = &derivation_path;
                async move {
                    let mut signing = givre::signing::<C>(j, key_share, signers, msg);
                    if !derivation_path.is_empty() {
                        signing = signing
                            .set_derivation_path(derivation_path.iter().copied())
                            .context("set derivation path")?;
                    }
                    if let Some(root) = taproot_merkle_root {
                        signing = signing.set_taproot_tweak(root).context("set merkle root")?
                    }

                    signing.sign(&mut rng, party).await.context("sign")
                }
            });

        let sigs: Vec<givre::signing::aggregate::Signature<_>> =
            futures::future::try_join_all(signing_executions)
                .await
                .unwrap();

        // Verify signature using external library
        C::verify_sig(
            &pk,
            key_shares[0].chain_code,
            &derivation_path,
            taproot_merkle_root,
            &sigs[0],
            msg,
        )
        .unwrap();

        for sig in &sigs[1..] {
            assert_eq!(sigs[0].r, sig.r);
            assert_eq!(sigs[0].z, sig.z);
        }
    }

    #[instantiate_tests(<givre::ciphersuite::Bitcoin>)]
    mod bitcoin {}
    #[instantiate_tests(<givre::ciphersuite::Secp256k1>)]
    mod secp256k1 {}
    #[instantiate_tests(<givre::ciphersuite::Ed25519>)]
    mod ed25519 {}
}
