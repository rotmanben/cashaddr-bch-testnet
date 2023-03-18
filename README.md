[![docs.rs](https://img.shields.io/docsrs/cashaddr)](https://docs.rs/cashaddr/latest/cashaddr/)
[![crates.io](https://img.shields.io/crates/v/cashaddr)](https://crates.io/crates/cashaddr)
[![loicense](https://img.shields.io/crates/l/cashaddr)](https://en.wikipedia.org/wiki/MIT_License)
[![gitlab build](https://img.shields.io/gitlab/pipeline-status/pezcore/cashaddr?branch=master)](https://gitlab.com/pezcore/cashaddr/-/pipelines/)


# Overview

A library crate providing a dependency-free, pure rust implementation of the
[cashaddr](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md)
codec. Allows for transcoding between hashes and cashaddr strings.

## Features

- Generalized interface supporting all standard and many non-standard use-cases
- Non-standard hash types (type bits)
- Arbitrary human-readable prefixes
- case-insensitive parsing
- Elided prefix
- Comprehensive error detection in decoder
- Convenience methods for succinct expression of common conversion parameters

## Limitations

Does not support [Forward Error
Correction](https://en.wikipedia.org/wiki/Error_correction_code#Forward_error_correction).
The [BCH Codes](https://en.wikipedia.org/wiki/BCH_code) used in the cashaddr
codec technically allow for forward error correction, but using them in Bitcoin
Cash address is dangerous and [strongly
dicouraged](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md#error-correction).

## About the Codec

Cashaddr is a base32-based encoding scheme designed to encode a hash digest
and hash type which describes the use case for the hash. The hash is an
arbitrary sequence of either 20, 24, 28, 32, 40, 48, 56, or 64 bytes. The
cashaddr format represents this information as a string which consists of 2
parts: an arbitrary user-defined prefix, and a base32-encoded representation of
the hash, hash type, hash length, and a checksum which checks both the hash
payload and the user prefix. For details, see the [cashaddr
spec](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md)

## Attribution
Most of the codec algorithm logic was copied from
[`bitcoincash-addr`](https://docs.rs/bitcoincash-addr/latest/bitcoincash_addr/).
This crate seeks to improve on `bitcoincash-addr` by providing a more
generalized and ergonomic user interface, adding support for arbitrary
prefixes, and reducing scope to only matters directly related the cashaddr
codec itself (base58check codec removed from scope).
