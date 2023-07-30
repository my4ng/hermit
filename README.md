# Hermit

## Introduction

Hermit is a simple, lightweight and secure file transfer client/server application written in asynchronous, safe Rust, based on the underlying Hermit protocol library.

Operationally, it relies on the [ring](https://github.com/briansmith/ring) cryptographic library and [async-std](https://github.com/async-rs/async-std) runtime to deliver authentication, confidentiality and integrity on top of reliable streams. By client verification of the server's pre-shared signature public key, it removes the requirement of a certificate authority (as in TLS) and enables a fully decentralized, self-hosted network.

## Cryptography

The hermit protocol uses the following cryptographic algorithms for the handshake and subsequent communication:

- Signature Algorithm: **EdDSA-Ed25519** ([RFC 8032](https://datatracker.ietf.org/doc/html/rfc8032))
- Key Exchange Algorithm: **ECDHE-X25519** ([RFC 7748](https://datatracker.ietf.org/doc/html/rfc7748))
- Key Derivation Function Algorithm: **HKDF-HMAC-SHA-256** ([RFC 5869](https://datatracker.ietf.org/doc/html/rfc5869))
- AEAD Algorithm: **AES_128_GCM** ([RFC 5116](https://datatracker.ietf.org/doc/html/rfc5116))
- Digest Algorithm: **SHA-256** ([FIPS PUB 180-4](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.180-4.pdf)) [^1]

[^1]: The digest function is only required to derive a shared "nonce base" (similar to the ["Per-Record Nonce"](https://datatracker.ietf.org/doc/html/rfc8446#section-5.3) used in TLS) that does not need to be cryptographically secure.

## Caution

Hermit is a personal project and has not been audited or reviewed, use at your own risk.

## License

Hermit is licensed under the [BSD-2-Clause Plus Patent License](https://spdx.org/licenses/BSD-2-Clause-Patent.html).

This license is designed to provide: a) a simple permissive license; b) that is compatible with the GNU General Public License (GPL), version 2; and c) which also has an express patent grant included.
