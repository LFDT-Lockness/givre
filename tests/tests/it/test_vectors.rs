//! Test vectors can be found in [Appendix F] of the draft
//!
//! [Appendix F]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html#name-test-vectors
use givre::{
    ciphersuite::Ciphersuite,
    generic_ec::{NonZero, Point, Scalar},
    key_share::{KeyInfo, Validate},
    signing::round1::{PublicCommitments, SecretNonces},
};
use hex_literal::hex;
use rand::{CryptoRng, RngCore};

struct TestVector<const T: usize, const N: usize> {
    public_key: &'static [u8],
    secret_key: &'static [u8],

    shares: [&'static [u8]; N],

    signers: [u16; T],
    commit_randomness: [&'static [u8]; T],
    expected_nonces: [[&'static [u8]; 2]; T],
    expected_commitments: [[&'static [u8]; 2]; T],

    msg: &'static [u8],

    expected_sig_shares: [&'static [u8]; T],

    expected_sig: [&'static [u8]; 2],
}

impl<const T: usize, const N: usize> TestVector<T, N> {
    fn carry_out<C: Ciphersuite>(&self) {
        let (t, n): (u16, u16) = (T.try_into().unwrap(), N.try_into().unwrap());

        let public_key = C::deserialize_point(self.public_key).unwrap();
        {
            let secret_key = C::deserialize_secret_scalar(self.secret_key).unwrap();
            assert_eq!(Point::generator() * &secret_key, public_key);
        }

        let shares = self
            .shares
            .map(|share| C::deserialize_secret_scalar(share).unwrap());
        let public_shares = shares
            .clone()
            .map(|share| Point::generator() * share)
            .to_vec();

        let share_preimages = (1..=n)
            .map(|j| NonZero::from_scalar(Scalar::<C::Curve>::from(j)))
            .collect::<Option<Vec<_>>>()
            .unwrap();

        let vss_setup = givre::key_share::VssSetup {
            min_signers: t,
            I: share_preimages,
        };

        let key_shares = (0..n)
            .zip(shares)
            .map(|(i, share)| {
                givre::key_share::DirtyKeyShare {
                    i,
                    key_info: givre::key_share::DirtyKeyInfo {
                        curve: Default::default(),
                        shared_public_key: public_key,
                        public_shares: public_shares.clone(),
                        vss_setup: Some(vss_setup.clone()),
                        chain_code: None,
                    },
                    x: share,
                }
                .validate()
                .unwrap()
            })
            .collect::<Vec<_>>();
        let key_info: &KeyInfo<_> = key_shares[0].as_ref();

        // --- Round 1
        let (nonces, commitments): (Vec<_>, Vec<_>) = self
            .signers
            .into_iter()
            .zip(self.commit_randomness)
            .map(|(j, randomness)| {
                givre::signing::round1::commit::<C>(
                    &mut mocked_randomness(randomness),
                    &key_shares[usize::from(j)],
                )
            })
            .unzip();

        // check that nonces match the vector
        {
            let expected_nonces =
                self.expected_nonces
                    .into_iter()
                    .map(|[hiding_nonce, binding_nonce]| SecretNonces {
                        hiding_nonce: C::deserialize_secret_scalar(hiding_nonce).unwrap(),
                        binding_nonce: C::deserialize_secret_scalar(binding_nonce).unwrap(),
                    });
            for (nonce, expected) in nonces.iter().zip(expected_nonces) {
                assert_eq!(nonce.hiding_nonce.as_ref(), expected.hiding_nonce.as_ref());
                assert_eq!(
                    nonce.binding_nonce.as_ref(),
                    expected.binding_nonce.as_ref()
                );
            }
        }
        // check that commitments match the vector
        {
            let expected_commitments =
                self.expected_commitments
                    .into_iter()
                    .map(|[hiding_comm, binding_comm]| PublicCommitments {
                        hiding_comm: C::deserialize_point(hiding_comm).unwrap(),
                        binding_comm: C::deserialize_point(binding_comm).unwrap(),
                    });
            for (comm, expected) in commitments.iter().zip(expected_commitments) {
                assert_eq!(*comm, expected);
            }
        }

        // --- Round 2
        let commitments_list = self
            .signers
            .into_iter()
            .zip(commitments.iter().copied())
            .collect::<Vec<_>>();
        let sig_shares = self
            .signers
            .into_iter()
            .zip(nonces)
            .zip(commitments)
            .map(|((j, nonces), commitment)| {
                let sig_share = givre::signing::round2::sign::<C>(
                    &key_shares[usize::from(j)],
                    nonces,
                    self.msg,
                    &commitments_list,
                )
                .unwrap();
                (j, commitment, sig_share)
            })
            .collect::<Vec<_>>();

        // check that sig shares match the vector
        {
            let expected = self
                .expected_sig_shares
                .into_iter()
                .map(|sig_share| C::deserialize_scalar(sig_share).unwrap());
            for ((_, _, sig_share), expected) in sig_shares.iter().zip(expected) {
                assert_eq!(sig_share.0, expected)
            }
        }

        // --- Aggregate
        let sig =
            givre::signing::aggregate::aggregate::<C>(&key_info, &sig_shares, self.msg).unwrap();

        {
            let r = C::deserialize_point(&self.expected_sig[0]).unwrap();
            let z = C::deserialize_scalar(&self.expected_sig[1]).unwrap();

            assert_eq!(*sig.r, r);
            assert_eq!(sig.z, z);
        }
    }
}

#[test]
fn secp256k1() {
    TestVector {
        public_key: &hex!("02f37c34b66ced1fb51c34a90bdae006901f10625cc06c4f64663b0eae87d87b4f"),
        secret_key: &hex!("0d004150d27c3bf2a42f312683d35fac7394b1e9e318249c1bfe7f0795a83114"),

        shares: [
            &hex!("08f89ffe80ac94dcb920c26f3f46140bfc7f95b493f8310f5fc1ea2b01f4254c"),
            &hex!("04f0feac2edcedc6ce1253b7fab8c86b856a797f44d83d82a385554e6e401984"),
            &hex!("00e95d59dd0d46b0e303e500b62b7ccb0e555d49f5b849f5e748c071da8c0dbc"),
        ],

        signers: [0, 2],
        commit_randomness: [
            &hex!(
                "7ea5ed09af19f6ff21040c07ec2d2adbd35b759da5a401d4c99dd26b82391cb2
                47acab018f116020c10cb9b9abdc7ac10aae1b48ca6e36dc15acb6ec9be5cdc5"
            ),
            &hex!(
                "e6cc56ccbd0502b3f6f831d91e2ebd01c4de0479e0191b66895a4ffd9b68d544
                7203d55eb82a5ca0d7d83674541ab55f6e76f1b85391d2c13706a89a064fd5b9"
            ),
        ],
        expected_nonces: [
            [
                &hex!("841d3a6450d7580b4da83c8e618414d0f024391f2aeb511d7579224420aa81f0"),
                &hex!("8d2624f532af631377f33cf44b5ac5f849067cae2eacb88680a31e77c79b5a80"),
            ],
            [
                &hex!("2b19b13f193f4ce83a399362a90cdc1e0ddcd83e57089a7af0bdca71d47869b2"),
                &hex!("7a443bde83dc63ef52dda354005225ba0e553243402a4705ce28ffaafe0f5b98"),
            ],
        ],
        expected_commitments: [
            [
                &hex!("03c699af97d26bb4d3f05232ec5e1938c12f1e6ae97643c8f8f11c9820303f1904"),
                &hex!("02fa2aaccd51b948c9dc1a325d77226e98a5a3fe65fe9ba213761a60123040a45e"),
            ],
            [
                &hex!("03077507ba327fc074d2793955ef3410ee3f03b82b4cdc2370f71d865beb926ef6"),
                &hex!("02ad53031ddfbbacfc5fbda3d3b0c2445c8e3e99cbc4ca2db2aa283fa68525b135"),
            ],
        ],

        msg: &hex!("74657374"),

        expected_sig_shares: [
            &hex!("c4fce1775a1e141fb579944166eab0d65eefe7b98d480a569bbbfcb14f91c197"),
            &hex!("0160fd0d388932f4826d2ebcd6b9eaba734f7c71cf25b4279a4ca2581e47b18d"),
        ],

        expected_sig: [
            &hex!("0205b6d04d3774c8929413e3c76024d54149c372d57aae62574ed74319b5ea14d0"),
            &hex!("c65dde8492a7471437e6c2fe3da49b90d23f642b5c6dbe7e36089f096dd97324"),
        ],
    }
    .carry_out::<givre::ciphersuite::Secp256k1>()
}

#[test]
fn ed25519() {
    TestVector {
        public_key: &hex!("15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673"),
        secret_key: &hex!("7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304"),

        shares: [
            &hex!("929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509"),
            &hex!("a91e66e012e4364ac9aaa405fcafd370402d9859f7b6685c07eed76bf409e80d"),
            &hex!("d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02"),
        ],

        signers: [0, 2],
        commit_randomness: [
            &hex!(
                "0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec
                69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501"
            ),
            &hex!(
                "86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f
                13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775"
            ),
        ],
        expected_nonces: [
            [
                &hex!("812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407"),
                &hex!("b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301"),
            ],
            [
                &hex!("c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e"),
                &hex!("243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d"),
            ],
        ],
        expected_commitments: [
            [
                &hex!("b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3"),
                &hex!("67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932"),
            ],
            [
                &hex!("cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91"),
                &hex!("7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552"),
            ],
        ],

        msg: &hex!("74657374"),

        expected_sig_shares: [
            &hex!("001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603"),
            &hex!("bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007"),
        ],

        expected_sig: [
            &hex!("36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbe"),
            &hex!("bd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b"),
        ],
    }
    .carry_out::<givre::ciphersuite::Ed25519>()
}

fn mocked_randomness(bytes: &[u8]) -> impl RngCore + CryptoRng + '_ {
    struct MockedRng<'b>(&'b [u8]);
    impl<'b> RngCore for MockedRng<'b> {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let len = dest.len();
            let (randomness, leftover) = self.0.split_at(len);
            dest.copy_from_slice(randomness);
            self.0 = leftover;
        }

        fn next_u32(&mut self) -> u32 {
            rand_core::impls::next_u32_via_fill(self)
        }
        fn next_u64(&mut self) -> u64 {
            rand_core::impls::next_u64_via_fill(self)
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
            Ok(self.fill_bytes(dest))
        }
    }
    impl<'b> CryptoRng for MockedRng<'b> {}

    MockedRng(bytes)
}
