/*
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

#ifndef __CHACHA20_AVX__
#define __CHACHA20_AVX__

#include <array>
#include <cstdint>
#include <cmath>
#include <immintrin.h>
#include <stdexcept>
#include <vector>

// Designed accordingly to: https://datatracker.ietf.org/doc/html/rfc8439
class Chacha20 {

    // Number of double rounds to perform
    static constexpr unsigned int ROUNDS = 10;  
    static constexpr unsigned int KEY_WORDS = 8;
    static constexpr unsigned int NONCE_WORDS = 3;
    static constexpr unsigned int STATE_SIZE = 16;
    static constexpr unsigned int ROW_SIZE = 4;

    // Internal state is made of 16 32-bit words
    // They are arranges as a 4x4 matrix as follows
    // 0 1 2 3
    // 4 5 6 7
    // 8 9 A B
    // C D E F
    // It is stored by rows and each row is stored twice for optimization used in double rounds
    // The only difference is block_count which is 1 greater in the second block
    std::array<__m256i, ROW_SIZE> internal_state;

    // Default constant words to be used for context initialization
    static constexpr std::array<std::uint32_t, 4> CONSTANT_WORDS = {
        0x61707865, // "expa"
        0x3320646e, // "nd 3"
        0x79622d32, // "2-by"
        0x6b206574  // "te k"
    };

    // Chacha variables defined upon construction
    std::array<std::uint32_t, KEY_WORDS> key;
    std::uint32_t block_count;
    std::array<std::uint32_t, NONCE_WORDS> nonce;

    /*------------------------------------------------
    Computes the result of bitwise left-rotating the value of x by s positions.
    This operation is also known as a left circular shift

    @param x integer to be left rotated
    @param s number of bits to rotate by
    @returns shifted value
    ------------------------------------------------*/
    static __m256i rotl_avx2(__m256i x, std::uint32_t s) {
        return _mm256_or_si256(_mm256_slli_epi32(x, s), _mm256_srli_epi32(x, 32 - s));
    }
    
    /*------------------------------------------------
    Computes the result of bitwise right-rotating the value of x by s positions.
    This operation is also known as a right circular shift

    @param x integer to be right rotated
    @param s number of bits to rotate by
    @returns shifted value
    ------------------------------------------------*/
    static __m256i rotr_avx2(__m256i x, std::uint32_t s) {
        return _mm256_or_si256(_mm256_slli_epi32(x, 32-s), _mm256_srli_epi32(x, s));
    }

    /*------------------------------------------------
    Computes the little-endian notation of a word x

    @param x integer to be left rotated
    @returns little-endian value
    ------------------------------------------------*/
    static inline std::uint32_t little_endian(std::uint32_t x) {
        return ((x & 0xFF000000) >> 24) |
               ((x & 0x00FF0000) >> 8)  |
               ((x & 0x0000FF00) << 8)  |
               ((x & 0x000000FF) << 24);
    }

    /*------------------------------------------------
    ChaCha20 double round function implemented with
    AVX2 256bit optimization. Thus it calculates
    two next states at the same time.

    @param rows array of 256 rows where first 128 bits will be
           first for chacha20 block and last 128 second chacha20 block
    ------------------------------------------------*/
    static void double_round(std::array<__m256i, ROW_SIZE>& state_cpy) {
        // Calculate columns
        state_cpy[0] = _mm256_add_epi32(state_cpy[0], state_cpy[1]);
        state_cpy[3] = _mm256_xor_si256(state_cpy[3], state_cpy[0]);
        state_cpy[3] = rotl_avx2(state_cpy[3], 16);
        
        state_cpy[2] = _mm256_add_epi32(state_cpy[2], state_cpy[3]);
        state_cpy[1] = _mm256_xor_si256(state_cpy[1], state_cpy[2]);
        state_cpy[1] = rotl_avx2(state_cpy[1], 12);
        
        state_cpy[0] = _mm256_add_epi32(state_cpy[0], state_cpy[1]);
        state_cpy[3] = _mm256_xor_si256(state_cpy[3], state_cpy[0]);
        state_cpy[3] = rotl_avx2(state_cpy[3], 8);
        
        state_cpy[2] = _mm256_add_epi32(state_cpy[2], state_cpy[3]);
        state_cpy[1] = _mm256_xor_si256(state_cpy[1], state_cpy[2]);
        state_cpy[1] = rotl_avx2(state_cpy[1], 7);
        
        // Shift so columns will now represent diagonals
        state_cpy[1] = _mm256_permutevar8x32_epi32(state_cpy[1], _mm256_set_epi32(6,5,4,7,2,1,0,3));
        state_cpy[2] = _mm256_permutevar8x32_epi32(state_cpy[2], _mm256_set_epi32(5,4,7,6,1,0,3,2));
        state_cpy[3] = _mm256_permutevar8x32_epi32(state_cpy[3], _mm256_set_epi32(4,7,6,5,0,3,2,1));
        
        // Calculate diagonals
        state_cpy[0] = _mm256_add_epi32(state_cpy[0], state_cpy[1]);
        state_cpy[3] = _mm256_xor_si256(state_cpy[3], state_cpy[0]);
        state_cpy[3] = rotl_avx2(state_cpy[3], 16);
        
        state_cpy[2] = _mm256_add_epi32(state_cpy[2], state_cpy[3]);
        state_cpy[1] = _mm256_xor_si256(state_cpy[1], state_cpy[2]);
        state_cpy[1] = rotl_avx2(state_cpy[1], 12);
        
        state_cpy[0] = _mm256_add_epi32(state_cpy[0], state_cpy[1]);
        state_cpy[3] = _mm256_xor_si256(state_cpy[3], state_cpy[0]);
        state_cpy[3] = rotl_avx2(state_cpy[3], 8);
        
        state_cpy[2] = _mm256_add_epi32(state_cpy[2], state_cpy[3]);
        state_cpy[1] = _mm256_xor_si256(state_cpy[1], state_cpy[2]);
        state_cpy[1] = rotl_avx2(state_cpy[1], 7);
        
        // Shift back so state is in it's original order
        state_cpy[1] = _mm256_permutevar8x32_epi32(state_cpy[1], _mm256_set_epi32(4,7,6,5,0,3,2,1));
        state_cpy[2] = _mm256_permutevar8x32_epi32(state_cpy[2], _mm256_set_epi32(5,4,7,6,1,0,3,2));
        state_cpy[3] = _mm256_permutevar8x32_epi32(state_cpy[3], _mm256_set_epi32(6,5,4,7,2,1,0,3));
    }

    /*------------------------------------------------
    Performs a block operation that is runs ROUNDS
    double_rounds on internal_state and then
    adds the outcome with internal_state before
    the operation.
    Does not modify block_count in any way of the state
    after the operation is applied.

    @param count block count to be used along key and nonce
    @return 2 next states after block operation
    ------------------------------------------------*/
    std::array<__m256i, ROW_SIZE> chacha20_block() {
        // modify the internal state to fit provided block_count
        // and increment block_count by 1 in second calculated state
        internal_state[3] = _mm256_add_epi32(internal_state[3], _mm256_set_epi32(2, 0, 0, 0, 2, 0, 0, 0));
        std::array<__m256i, ROW_SIZE> state_cpy = internal_state; 

        for(unsigned i = 0; i < ROUNDS; i++) {
            double_round(state_cpy);
        }

        // Matrix addition of state_cpy and internal_state for both states at once
        for(size_t i = 0; i < ROW_SIZE; i++) {
            state_cpy[i] = _mm256_add_epi32(state_cpy[i], internal_state[i]);
        }

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
        // Assign constant words
        internal_state[0] = _mm256_set_epi32(CONSTANT_WORDS[0], CONSTANT_WORDS[1], CONSTANT_WORDS[2], CONSTANT_WORDS[3],
                                        CONSTANT_WORDS[0], CONSTANT_WORDS[1], CONSTANT_WORDS[2], CONSTANT_WORDS[3]);

        // Assign key and translate them into little-endian
        internal_state[1] = _mm256_set_epi32(little_endian(key[0]), little_endian(key[1]), little_endian(key[2]), little_endian(key[3]), 
                                        little_endian(key[0]), little_endian(key[1]), little_endian(key[2]), little_endian(key[3]));
        internal_state[2] = _mm256_set_epi32(little_endian(key[4]), little_endian(key[5]), little_endian(key[6]), little_endian(key[7]), 
                                        little_endian(key[4]), little_endian(key[5]), little_endian(key[6]), little_endian(key[7]));
        // Assign block_count and nonce
        // Block_count-2 since block_count is incremented by 2 before encryption by chacha20_block
        // Block_count-1 since second block should be 1 greater than first block
        internal_state[3] = _mm256_set_epi32(block_count-2, little_endian(nonce[0]), little_endian(nonce[1]), little_endian(nonce[2]),
                                        block_count-1, little_endian(nonce[0]), little_endian(nonce[1]), little_endian(nonce[2]));
    }

    /*------------------------------------------------
    Sets all bits of arr to 0 in a cryptographically safe way.

    @param arr Array to be zeroed
    ------------------------------------------------*/
    template<typename T, size_t N>
    void secure_zero(std::array<T, N>& arr) {
        volatile T* p = reinterpret_cast<volatile T*>(arr.data());
        for (size_t i = 0; i < N; ++i) {
            p[i] = 0;
        }
    }

public:
    /*------------------------------------------------
    Since chacha works on words both key and nonce are
    separated into an array of 32bit unsigned ints.
    Words within arrays are to be ordered by big-endian.
    The most significant word is array's first element.
    The least significant word is array's last element.

    key consists of 256bits (8*32)
    block count consits of 32bits
    nonce consists of 96bits (3*32)
    ------------------------------------------------*/
    explicit Chacha20(const std::array<std::uint32_t, KEY_WORDS>& key, std::uint32_t block_count, const std::array<std::uint32_t, NONCE_WORDS>& nonce):
    key ( key), block_count ( block_count), nonce ( nonce) {
        init();
    }

    /*------------------------------------------------
    Upon destruction 0 all sensetive data
    ------------------------------------------------*/
    ~Chacha20() {
        secure_zero(key);
        block_count = 0;
        secure_zero(nonce);
        
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
    std::vector<std::uint8_t> encrypt(const std::vector<std::uint8_t>& message) {
        std::vector<std::uint8_t> output(message.size()); // length of output always == length of input
        size_t message_idx = 0;

        while(message_idx < message.size()) {
            std::array<__m256i, ROW_SIZE> stream = chacha20_block();
            // translate stream into a friendly type
            // elements are in reverse order
            std::array<std::array<std::uint32_t, ROW_SIZE*2>, 4> stream_arr;
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(&stream_arr[0]), stream[0]);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(&stream_arr[1]), stream[1]);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(&stream_arr[2]), stream[2]);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(&stream_arr[3]), stream[3]);

            // Iteration is done by byte not word, thus STATE_SIZE*4 since STATE_SIZE is measured in words
            // Since stream has 2 states, we multiply it further by 2 STATE_SIZE*4*2 = STATE_SIZE*8
            for(size_t stream_idx = 0, row = 0, corr = 0, arr_idx = 0;
                stream_idx < STATE_SIZE*8 && message_idx < message.size();
                stream_idx++, message_idx++, arr_idx++
            ) {
                /*  Apply XOR on each byte of the word after 4 full iterations of the for loop.
                    stream[stream_idx/4] word has 4 bytes, so XOR must be applied 4 times for each word in stream.
                    >>8*(i%4) shifts by 0 8 16 24 so that XOR is applied through all bytes of word.
                    Word is XORed with a byte, thus only the least significant byte is XORed each time.
                */     
                if(arr_idx/4 == ROW_SIZE) row++, arr_idx = 0;      
                if(row == ROW_SIZE) corr = ROW_SIZE, row = 0; 
                output[message_idx] = message[message_idx] ^ (stream_arr[row][7-arr_idx/4-corr]>>(8*(stream_idx%4)));
            }
        }

        return output;
    }
};

#endif /* #ifndef __CHACHA20_AVX__ */