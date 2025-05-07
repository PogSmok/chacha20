# ChaCha20 cipher
ChaCha20 is a stream cipher designed by Daniel J. Bernstein that provides high-speed encryption with strong security guarantees. It is an evolution of the earlier Salsa20 cipher, featuring improved security and performance characteristics.
ChaCha20 is widely regarded as secure when used correctly, especially with a unique nonce for each message. It is commonly used in protocols like TLS, VPNs, and secure messaging systems due to its speed and security properties.

## RFC Compliance

The core of this implementation follows the official [RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439) specification for ChaCha20. This ensures compatibility with the official standard, including test vectors, initialization procedures, and processing steps. The implementation emphasizes:

- **Correctness**
- **Security**
- **Performance**

Making it suitable for integration into cryptographic systems that require high-speed and secure stream cipher operations.

## Features

- **Fast and secure stream cipher** based on the ChaCha20 algorithm
- Supports **256-bit keys** and **96-bit nonces**
- Full support for **encryption** and **decryption** (symmetric cipher)
- **Modular design**, easy to integrate into your projects
- **Safe, exception-free code**
- Optimized for **AVX2** for better performance on supported hardware

## Usage

To use the ChaCha20 implementation, simply download `chacha20.hpp` or `chacha20_AVX.hpp` (if your machine supports AVX) and include it in your project like any other header file.

You can construct a `Chacha20` object by providing a **key**, a **nonce**, and a **block count**. Afterward, use the `encrypt()` function to encode or decode your strings.

For a complete example, refer to `test.cpp`.

# IMPORTANT!
To run program using AVX instructions compile with 
```
g++ -mavx -march=native ...
```

## Benchmark Results
Below are the benchmark results for ChaCha20 encryption performance (compiled with g++), comparing the non-AVX and AVX implementations, as well as optimizations with `-O3` flag.


### ChaCha20 (Without AVX Optimization)

<div align="center">
 
#### CHACHA20 (No Optimization)
| Test Case | Total Time (ms) | Time Per Run (ms) |
|-----------|------------------|-------------------|
| Test 1    | 740.125          | 0.00740125        |
| Test 2    | 385.856          | 0.00385856        |
| Test 3    | 2157.17          | 0.0215717         |
| Test 4    | 743.133          | 0.00743133        |
| **Total** | **4026.274**     | **0.004026274**   |

#### CHACHA20 AVX (No Optimization)
| Test Case | Total Time (ms) | Time Per Run (ms) |
|-----------|------------------|-------------------|
| Test 1    | 354.751          | 0.00354751        |
| Test 2    | 321.103          | 0.00321103        |
| Test 3    | 1102.97          | 0.0110297         |
| Test 4    | 375.859          | 0.00375859        |
| **Total** | **2154.683**     | **0.02154683**    |

----

#### CHACHA20 (Optimized `-O3`)
| Test Case | Total Time (ms) | Time Per Run (ms) |
|-----------|------------------|-------------------|
| Test 1    | 49.3332          | 0.000493332       |
| Test 2    | 30.0358          | 0.000300358       |
| Test 3    | 134.503          | 0.00134503        |
| Test 4    | 50.9175          | 0.000509175       |
| **Total** | **264.79**       | **0.0026479**     |

#### CHACHA20 AVX (Optimized `-O3`)
| Test Case | Total Time (ms) | Time Per Run (ms) |
|-----------|------------------|-------------------|
| Test 1    | 44.8081          | 0.000448081       |
| Test 2    | 34.3614          | 0.000343614       |
| Test 3    | 127.476          | 0.00127476        |
| Test 4    | 48.1312          | 0.000481312       |
| **Total** | **254.7767**     | **0.002547767**   |
</div>

