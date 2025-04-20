/*
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

#ifndef __CHACHA20__
#define __CHACHA20__

#include <cstdint>
#include <vector>
#include <stdexcept>
#include <algorithm>
#include <cmath>

// Built following documentation: https://datatracker.ietf.org/doc/html/rfc8439
class Chacha20 {

    // Number of double rounds to perform
    const unsigned int ROUNDS = 10;

    // Internal state is made of 16 32-bit words
    // They are arranged as a 4x4 matrix as follows
    // 0 1 2 3
    // 4 5 6 7
    // 8 9 A B
    // C D E F
    const unsigned int INTERNAL_SIZE = 16;
    std::vector<std::uint32_t> internal_state;

    // Chacha variables defined upon construction
    std::vector<std::uint32_t> key;
    std::uint32_t block_count;
    std::vector<std::uint32_t> nonce;

    // Default constant words to be used for context initialization
    const std::vector<std::uint32_t> CONSTANT_WORDS {
        0x61707865, // "expa"
        0x3320646e, // "nd 3"
        0x79622d32, // "2-by"
        0x6b206574  // "te k"
    };

    /*------------------------------------------------
    Computes the result of bitwise left-rotating the value of x by s positions.
    This operation is also known as a left circular shift

    @param x integer to be left rotated
    @param s number of bits to rotate by
    @returns shifted value
    ------------------------------------------------*/
    std::uint32_t rotl(std::uint32_t x, std::uint32_t s) {
        return (x << s) | (x >> (sizeof(x)*8-s));
    }

    /*------------------------------------------------
    Computes the little-endian notation of a word x

    @param x integer to be left rotated
    @returns little-endian value
    ------------------------------------------------*/
    std::uint32_t little_endian(std::uint32_t x) {
        return ((x & 0xFF000000) >> 24) |
               ((x & 0x00FF0000) >> 8)  |
               ((x & 0x0000FF00) << 8)  |
               ((x & 0x000000FF) << 24);
    }

    /*------------------------------------------------
    ChaCha20 quarter round function
    Two quarter rounds make a full round
    Four quarter rounds make a double round

    @param a word a in chacha quarter round algorithm
    @param b word b in chacha quarter round algorithm
    @param c word c in chacha quarter round algorithm
    @param d word d in chacha quarter round algorithm
    ------------------------------------------------*/
    void quarter_round(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d) {
        a += b; d ^= a; d = rotl(d, 16);
        c += d; b ^= c; b = rotl(b, 12);
        a += b; d ^= a; d = rotl(d, 8);
        c += d; b ^= c; b = rotl(b, 7);
    }

    /*------------------------------------------------
    Performs a single double round function, alternating
    accordingly between columns and diagonals. This
    function should be called ROUNDS times to encrypt
    the state.

    @param state_cpy copy of internal_state to perform rounds on
    ------------------------------------------------*/
    void double_round(std::vector<std::uint32_t>& state_cpy) {
        // column rounds
        quarter_round(state_cpy[0], state_cpy[4], state_cpy[8], state_cpy[12]);
        quarter_round(state_cpy[1], state_cpy[5], state_cpy[9], state_cpy[13]);
        quarter_round(state_cpy[2], state_cpy[6], state_cpy[10], state_cpy[14]);
        quarter_round(state_cpy[3], state_cpy[7], state_cpy[11], state_cpy[15]);

        // diagonal rounds
        quarter_round(state_cpy[0], state_cpy[5], state_cpy[10], state_cpy[15]);
        quarter_round(state_cpy[1], state_cpy[6], state_cpy[11], state_cpy[12]);
        quarter_round(state_cpy[2], state_cpy[7], state_cpy[8], state_cpy[13]);
        quarter_round(state_cpy[3], state_cpy[4], state_cpy[9], state_cpy[14]);
    }

    /*------------------------------------------------
    Performs a block operation that is runs ROUNDS
    double_rounds on internal_state and then
    adds the outcome with internal_state before
    the operation.

    @param count block count to be used along key and nonce
    @return state after block operation
    ------------------------------------------------*/
    std::vector<std::uint32_t> chacha20_block(std::uint32_t count) {
        // modify the internal state to fit provided block_count
        internal_state[12] = count;

        std::vector<std::uint32_t> state_cpy = internal_state;
        for(int i = 0; i < ROUNDS; i++) {
            double_round(state_cpy);
        }

        // Matrix addition of state_cpy and internal_state
        for(int i = 0; i < INTERNAL_SIZE; i++) {
            state_cpy[i] += internal_state[i];
        }

        // return internal_state to it's initial state
        internal_state[12] = block_count;

        return state_cpy;
    }

    /*------------------------------------------------
    Initialize internal state with given key, nonce and block count.

    The ChaCha20 state is initialized as follows: (https://datatracker.ietf.org/doc/html/rfc8439)

    The first four words (0-3) are constants: 0x61707865, 0x3320646e,
      0x79622d32, 0x6b206574.

    The next eight words (4-11) are taken from the 256-bit key by
      reading the bytes in little-endian order, in 4-byte chunks.

    Word 12 is a block counter.  Since each block is 64-byte, a 32-bit
      word is enough for 256 gigabytes of data.

    Words 13-15 are a nonce, which MUST not be repeated for the same
      key.  The 13th word is the first 32 bits of the input nonce taken
      as a little-endian integer, while the 15th word is the last 32
      bits.

       cccccccc  cccccccc  cccccccc  cccccccc
       kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
       kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
       bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn

    c=constant k=key b=blockcount n=nonce
    ------------------------------------------------*/
    void init() {
        // initialize internal state vector
        internal_state = std::vector<std::uint32_t>(INTERNAL_SIZE);

        // Assign constant words
        internal_state[0] = CONSTANT_WORDS[0];
        internal_state[1] = CONSTANT_WORDS[1];
        internal_state[2] = CONSTANT_WORDS[2];
        internal_state[3] = CONSTANT_WORDS[3];

        // Assign key and translate them into little-endian
        internal_state[4] = little_endian(key[0]);
        internal_state[5] = little_endian(key[1]);
        internal_state[6] = little_endian(key[2]);
        internal_state[7] = little_endian(key[3]);
        internal_state[8] = little_endian(key[4]);
        internal_state[9] = little_endian(key[5]);
        internal_state[10] = little_endian(key[6]);
        internal_state[11] = little_endian(key[7]);

        // Assign block_count
        internal_state[12] = block_count;

        // Assign nonce and translate them into little-endian
        internal_state[13] = little_endian(nonce[0]);
        internal_state[14] = little_endian(nonce[1]);
        internal_state[15] = little_endian(nonce[2]);
    }

public:
    /*------------------------------------------------
    Since chacha works on words both key and nonce are
    separated into a vector of 32bit unsigned ints.
    Words within vectors are to be ordered by big-endian.
    The most significant word is vector's first element.
    The least significant word is vector's last element.

    key consists of 256bits (8*32)
    block count consits of 32bits
    nonce consists of 96bits (3*32)
    ------------------------------------------------*/
    Chacha20(std::vector<std::uint32_t> key, std::uint32_t block_count, std::vector<std::uint32_t> nonce) {
        if(key.size() != 8) throw std::invalid_argument("Key must consist of exactly 8 words.\n");
        if(nonce.size() != 3) throw std::invalid_argument("Nonce must consist of exactly 3 words.\n");

        this->key = key;
        this->block_count = block_count;
        this->nonce = nonce;

        // initialize state
        init();
    }

    /*------------------------------------------------
    Performs encryption/decryption on the given message.
    Function successively calls chacha20_block() with
    the same key and nonce while incrementing the 
    block_count of inner state after each call.
    The result is concatenated and ordered by little-endian 
    then XORed with the message resulting in encryption.
    Encrypted message is guaranteed to have the same 
    length as the input message.

    @param message Message for encryption or decryption
    @return Encrypted/Decrypted message
    ------------------------------------------------*/
    std::string encrypt(std::string message) {
        std::string encrypted;
        for(int i = 0; i < std::floor(message.length()/64); i++) {
            std::vector<std::uint32_t> stream = chacha20_block(block_count+i);
            // XOR stream with appropiate block of message
            for(int j = i*64, t = 0; j < i*64+64; t++) {
                // stream must be little-endian when XORing
                std::uint32_t little = little_endian(stream[t]);
                encrypted += message[j++] ^ (little>>24);
                encrypted += message[j++] ^ (little>>16);
                encrypted += message[j++] ^ (little>>8);
                encrypted += message[j++] ^ (little);
            }
        } 

        // Handle the remaning not full block if exists
        if(message.length() % 64 != 0) {
            int i = std::floor(message.length()/64);
            std::vector<std::uint32_t> stream = chacha20_block(block_count+i);
            // XOR stream with appropiate block of message
            for(int j = i*64, t = 0; j < message.length(); t++) {
                // stream must be little-endian when XORing
                std::uint32_t little = little_endian(stream[t]);
                encrypted += message[j++] ^ (little>>24);
                if(j == message.length()) continue;
                encrypted += message[j++] ^ (little>>16);
                if(j == message.length()) continue;
                encrypted += message[j++] ^ (little>>8);
                if(j == message.length()) continue;
                encrypted += message[j++] ^ (little);
            }
        }

        return encrypted;
    }
};

#endif /* #ifndef __CHACHA20__ */
