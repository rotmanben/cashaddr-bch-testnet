# cashaddr

A library crate providing a dependency-free, pure rust implementation of the
[cashaddr](https://github.com/bitcoincashorg/bitcoincash.org/blob/master/spec/cashaddr.md)
codec.

## Features

- Trait based interface for encoding arbitrary sequence of bytes to cashaddr
  Strings
- Generalized interface supporting all standard and many non-standard use-cases
- Convenience methods for succinct expression of common conversion parameters
- Arbitrary prefixes
- Descriptive error types
- Payload for encapsulating parsed cashaddr payload

## About the Codec

Cashaddr is a base32-based encoding scheme designed to encode a hash digest
and hash type which describes the use case for the hash. The hash is an
arbitrary sequence of either 20, 24, 28, 32, 40, 48, 56, or 64 bytes. The
cashaddr format represents this information as a string which consists of 2
parts: an arbitrary user-defined prefix, and a base32-encoded representation of
the hash, hash type, and a checksum which checks both the hash payload and the
user prefix.

## Attribution
Most of the codec algorithm logic was copied from
[`bitcoincash-addr`](https://docs.rs/bitcoincash-addr/latest/bitcoincash_addr/).
This crate seeks to improve on `bitcoincash-addr` a more generalized and
convenient user interface, reducing scope as well as support arbitrary
prefixes.
