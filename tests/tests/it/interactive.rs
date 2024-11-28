#[generic_tests::define(attrs(test_case::case))]
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
    fn keygen_sign<C: Ciphersuite + ExternalVerifier>(t: Option<u16>, n: u16) {
        let mut rng = rand_dev::DevRng::new();

        // --- Keygen
        let eid: [u8; 32] = rng.gen();
        let eid = givre::keygen::ExecutionId::new(&eid);

        let mut sim_threshold = round_based::simulation::Simulation::with_capacity(n);
        let mut sim_nonthreshold = round_based::simulation::Simulation::with_capacity(n);
        for j in 0..n {
            let mut rng = rng.fork();
            if let Some(t) = t {
                sim_threshold.add_async_party(|party| async move {
                    givre::keygen::<C::Curve>(eid, j, n)
                        .set_threshold(t)
                        .hd_wallet(true)
                        .start(&mut rng, party)
                        .await
                })
            } else {
                sim_nonthreshold.add_async_party(|party| async move {
                    givre::keygen(eid, j, n)
                        .hd_wallet(true)
                        .start(&mut rng, party)
                        .await
                })
            }
        }

        let key_shares = if t.is_some() {
            sim_threshold.run()
        } else {
            sim_nonthreshold.run()
        };
        let key_shares = key_shares.unwrap().expect_ok().into_vec();
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

        let sig = round_based::simulation::run_with_setup(signers, |j, party, &index_at_keygen| {
            let key_share = &key_shares[usize::from(index_at_keygen)];
            let derivation_path = &derivation_path;
            let mut rng = rng.fork();
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
        })
        .unwrap()
        .expect_ok()
        .expect_eq();

        // Verify signature using external library
        C::verify_sig(
            &pk,
            key_shares[0].chain_code,
            &derivation_path,
            taproot_merkle_root,
            &sig,
            msg,
        )
        .unwrap();
    }

    #[instantiate_tests(<givre::ciphersuite::Bitcoin>)]
    mod bitcoin {}
    #[instantiate_tests(<givre::ciphersuite::Secp256k1>)]
    mod secp256k1 {}
    #[instantiate_tests(<givre::ciphersuite::Ed25519>)]
    mod ed25519 {}
}
