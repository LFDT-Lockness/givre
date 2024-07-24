## Threshold Schnorr implementation based on [FROST IETF Draft][draft]

[FROST][draft] is state of art protocol for Threshold Schnorr Signatures that supports 1-round signing (requires
signers to commit nonces ahead of time), and identifiable abort.

This crate provides:
* Distributed Key Generation (DKG) \
  FROST does not define DKG protocol to be used. We simply re-export DKG based on [CGGMP21] implementation
  when `cggmp21-keygen` feature is enabled, which is a fairly reasonable choice as it's proven to be UC-secure.
  Alternatively, you can use any other UC-secure DKG protocol.
* FROST Signing \
  We provide API for both manual signing execution (for better flexibility and efficiency) and interactive protocol
  (for easier usability and fool-proof design), see `signing` module for details.
* Trusted dealer (importing key into TSS)
* reconstruct_secret_key (exporting key from TSS)

This crate doesn't support (currently):
* Identifiable abort

The crate is wasm and no_std friendly.

## How to use the library

### Distributed Key Generation (DKG)
First of all, you need to generate a key. For that purpose, you can use any secure
(preferably, UC-secure) DKG protocol. FROST IETF Draft does not define any DKG
protocol or requirements it needs to meet, so the choice is up to you. This library
re-exports CGGMP21 DKG from `cggmp21-keygen` crate when `cggmp21-keygen` feature
is enabled which is proven to be UC-secure and should be a reasonable default.

CGGMP21 DKG is an interactive protocol built on `round_based` framework. In order
to carry it out, you need to define the transport layer (i.e. how the signers can
communicate with each other). It's simply a pair of stream and sink:

```rust
let incoming: impl Stream<Item = Result<Incoming<Msg>>>;
let outgoing: impl Sink<Outgoing<Msg>>;
```

where:
* `Msg` is a protocol message (e.g., `keygen::msg::threshold::Msg`)
* `round_based::Incoming` and `round_based::Outgoing` wrap `Msg` and provide additional data (e.g., sender/recipient)
* `futures::Stream` and `futures::Sink` are well-known async primitives.


Transport layer implementation needs to meet requirements:
* All messages must be authenticated \
  Whenever one party receives a message from another, the receiver should cryptographically
  verify that the message comes from the claimed sender.
* All p2p messages must be encrypted \
  Only the designated recipient should be able to read the message

Then, construct an MpcParty:
```rust
let delivery = (incoming, outgoing);
let party = round_based::MpcParty::connected(delivery);
```

Now, you can finally execute the DKG protocol. The protocol involves all signers
who will co-share a key. All signers need to agree on some basic parameters including
the participants’ indices, the execution ID, and the threshold value (i.e., t).
```rust
use givre::ciphersuite::{Ciphersuite, Secp256k1};

let eid = givre::keygen::ExecutionId::new(b"execution id, unique per protocol execution");
let i = /* signer index (0 <= i < n) */;
let n = /* number of signers taking part in key generation */;
let t = /* threshold */;

let key_share = givre::keygen::<<Secp256k1 as Ciphersuite>::Curve>(eid, i, n)
    .set_threshold(t)
    .start(&mut OsRng, party)
    .await?;
```

### Signing
FROST signing can be carried out either interactively with the help of `round_based`
framework, or manually.

#### Manual Signing
In the manual signing, as the name suggests, you manually construct all messages
and drive the protocol. It gives you better control over protocol execution and
you can benefit from better performance (e.g. by having 1 round signing). However,
it also gives a greater chance of misusing the protocol and violating security.
When opting for manual signing, make sure you're familiar with the [FROST IETF Draft][draft].
Refer to `signing` module docs for the instructions.

#### Interactive Signing (requires `full-signing` feature)
Interactive Signing has more user-friendly interface and harder-to-misuse design.
It works on top of `round_based` framework similarly to DKG described above.
As before, you need to define a secure transport layer and construct MpcParty.
Then, you need to assign each signer a unique index, in range from 0 to t-1. The
signers also need to know which index each of them occupied at the time of keygen.

```rust
use givre::ciphersuite::Secp256k1;

let i = /* signer index (0 <= i < min_signers) */;
let parties_indexes_at_keygen: [u16; MIN_SIGNERS] =
    /* parties_indexes_at_keygen[i] is the index the i-th party had at keygen */;
let key_share = /* key share */;

let data_to_sign = b"data to be signed";

let signature = givre::signing::<Secp256k1>(i, &key_share, &parties_indexes_at_keygen, data_to_sign)
    .sign(&mut OsRng, party)
    .await?;
```
### Signer indices
We use indices to uniquely refer to particular signers sharing a key. Each
index `i` is an unsigned integer `u16` with `0 ≤ i < n` where `n` is the
total number of participants in the protocol.

All signers should have the same view about each others’ indices. For instance,
if Signer A holds index 2, then all other signers must agree that i=2 corresponds
to Signer A.

Assuming some sort of PKI (which would anyway likely be used to ensure secure
communication, as described above), each signer has a public key that uniquely
identifies that signer. It is then possible to assign unique indices to the signers
by lexicographically sorting the signers’ public keys, and letting the index of a
signer be the position of that signer’s public key in the sorted list.

## Webassembly and `no_std` support
This crate is compatible with `wasm32-unknown-unknown` target and `no_std`. Requires
disabling `std` feature which is on by default.

[CGGMP21]: https://github.com/dfns/cggmp21
[draft]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html
