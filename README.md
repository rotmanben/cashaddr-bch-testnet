[![docs.rs](https://img.shields.io/docsrs/cashaddr)](https://docs.rs/cashaddr/latest/cashaddr/)
[![crates.io](https://img.shields.io/crates/v/cashaddr)](https://crates.io/crates/cashaddr)
[![loicense](https://img.shields.io/crates/l/cashaddr)](https://en.wikipedia.org/wiki/MIT_License)
[![gitlab build](https://img.shields.io/gitlab/pipeline-status/pezcore/cashaddr?branch=master)](https://gitlab.com/pezcore/cashaddr/-/pipelines/)


# Overview

A library crate providing a dependency-free<sup>†</sup>, pure rust
implementation of the
[cashaddr](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md)
codec. Allows for transcoding between hashes and cashaddr strings.

† This Crate is only dependency-free if no optional crate features are enabled:
enabling crate features can introduce third-party dependencies.

## Features

- Generalized interface supporting all standard and many non-standard use-cases
- Non-standard hash types (type bits)
- Arbitrary human-readable prefixes
- Case-insensitive parsing
- Elided prefix
- Comprehensive error detection in decoder
- Convenience methods for succinct expression of common conversion parameters

## Feature Flags

All crate features are disabled by default. The following optional crate
features can be enabled to provide additional functionality:

- `convert` enables the [`convert`] module which provides functions for
converting between cashaddr addresses and legacy Bitcoin addresses.

## Limitations

Does not support [Forward Error
Correction](https://en.wikipedia.org/wiki/Error_correction_code#Forward_error_correction).
The [BCH Codes](https://en.wikipedia.org/wiki/BCH_code) used in the cashaddr
codec technically allow for forward error correction, but using FEC in Bitcoin
Cash addresses is dangerous and [strongly
discouraged](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md#error-correction).

## About the Codec

Cashaddr is a base32-based encoding scheme designed to encode a [hash
digest](https://en.wikipedia.org/wiki/Hash_function) and hash type, which
describes the use case for the hash, as a string. A cashaddr string consists of
2 distinct parts separated by a colon (`:`) in the following order:

1. An arbitrary user-defined prefix, sometimes referred to as the
   "human-readable prefix", the semantics of which are up to the application
   using cashaddr
2. A binary payload which is encoded as a
   [base32](https://en.wikipedia.org/wiki/Base32) string using a specific
   alphabet. This payload contains the following fields:
    1. Hash type: one of 16 values which describe the intended use-case for the
       hash. see [`HashType`]
    2. Hash length: one of 8 numeric values which describe the length of the
       hash. Used in verifying cashaddr string
    3. The hash itself, which is an arbitrary sequence of 20, 24, 28, 32, 40,
       48, 56, or 64 bytes
    4. A 40-bit checksum which checks the entire cashaddr, including the
       user-defined prefix.

Together with the length field, the checksum provides extremely strong
assurance that a received cashaddr string was not corrupted in transmission.

Currently, the only widespread use of cashaddr is for encoding [Bitcoin
Cash](https://bitcoincash.org/) addresses, but its design features make it
an attractive choice for a general-purpose text codec for hashes.

For details, see the [cashaddr
spec](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md)

## Attribution
Most of the codec algorithm logic was based on
[`bitcoincash-addr`](https://docs.rs/bitcoincash-addr/latest/bitcoincash_addr/).
This crate seeks to improve on `bitcoincash-addr` by providing a more
generalized and ergonomic user interface, adding support for arbitrary
prefixes, and reducing scope to only matters directly related the cashaddr
codec itself (base58check codec removed from scope).
