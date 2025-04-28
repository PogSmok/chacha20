# ChaCha20 cipher
ChaCha20 is a stream cipher designed by Daniel J. Bernstein that provides high-speed encryption with strong security guarantees. It is an evolution of the earlier Salsa20 cipher, featuring improved security and performance characteristics.
ChaCha20 is widely regarded as secure when used correctly, especially with a unique nonce for each message. It is commonly used in protocols like TLS, VPNs, and secure messaging systems due to its speed and security properties.

## The core of the implementation follows the [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) specification for ChaCha20.
This library ensures compatibility with the official standard, including test vectors, initialization procedures, and processing steps.
The implementation emphasizes correctness, security, and performance, making it suitable for integration into cryptographic systems requiring high-speed and secure stream cipher operations.

## Features:
  * Fast and secure stream cipher based on the ChaCha20 algorithm
  * 256-bit keys and 96-bit nonces
  * Implementation of encryption and decryption (since it's a symmetric cipher)
  * Modular and easy to integrate into your projects
  * Safe and exception-free code
  * Optimized AVX2 implementation

## Usage
Simply download the `chacha20.hpp` or `chacha20_AVX.hpp` if your machine supports AVX and include it like any other header. This will allow the construction of a `Chacha20` object with a user-provided key, block count and nonce.
Afterwards simply call `encrypt()` function on whatever string is to be encoded or decoded. For an example refer to `test.cpp`. To run program using AVX instructions compile with ```-mavx -march=native``` flags.
