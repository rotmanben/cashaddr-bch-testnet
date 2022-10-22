![docs.rs](https://img.shields.io/docsrs/cashaddr)
![crates.io](https://img.shields.io/crates/v/cashaddr)
![loicense](https://img.shields.io/crates/l/cashaddr)


# Overview

A library crate providing a dependency-free, pure rust implementation of the
[cashaddr](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md)
codec.

## Features

- Trait based interfaces for transcoding arbitrary sequence of bytes to/from
  cashaddr Strings
- Generalized interface supporting all standard and many non-standard use-cases
- Convenience methods for succinct expression of common conversion parameters
- Custom hash types
- Arbitrary prefixes
- Elided prefix
- Descriptive error types
- Payload struct for encapsulating parsed cashaddr payload and hash type

## About the Codec

Cashaddr is a base32-based encoding scheme designed to encode a hash digest
and hash type which describes the use case for the hash. The hash is an
arbitrary sequence of either 20, 24, 28, 32, 40, 48, 56, or 64 bytes. The
cashaddr format represents this information as a string which consists of 2
parts: an arbitrary user-defined prefix, and a base32-encoded representation of
the hash, hash type, and a checksum which checks both the hash payload and the
user prefix. For details, see the [cashaddr
spec](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md)

## Attribution
Most of the codec algorithm logic was copied from
[`bitcoincash-addr`](https://docs.rs/bitcoincash-addr/latest/bitcoincash_addr/).
This crate seeks to improve on `bitcoincash-addr` by providing a more
generalized and ergonomic user interface, adding support for arbitrary
prefixes, and reducing scope to only matters directly related the cashaddr
codec itself (base58check codec removed from scope).
