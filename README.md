Threshold Schnorr implementation based on [FROST IETF Draft][draft]

FROST is state of art protocol for Threshold Schnorr Signatures that supports 1-round signing (requires signers to
commit nonces ahead of time), and identifiable abort.

This crate provides:
* Threshold and non-threshold Distributed Key Generation (DKG) \
  Note that FROST does not define DKG protocol to be used. We simply re-export DKG based on [CGGMP21] implementation
  when `cggmp21-keygen` feature is enabled. Alternatively, you can use any other UC-secure DKG protocol.
* FROST Signing \
  We provide API for both manual signing execution (for better flexibility and efficiency) and interactive protocol
  (for easier usability and fool-proof design), see signing module for details.
* Trusted dealer (importing key into TSS)

This crate doesn't support (currently):
* Identifiable abort

[CGGMP21]: https://github.com/dfns/cggmp21
[draft]: https://www.ietf.org/archive/id/draft-irtf-cfrg-frost-15.html
