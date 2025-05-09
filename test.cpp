//#include "chacha20_AVX.hpp"
#include "chacha20.hpp"  // Including ChaCha20 header

#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace util {

// Converts a hex string into a vector of uint32_t (8 hex chars per int)
std::vector<std::uint32_t> hex_str_to_vec(const std::string& str) {
    std::vector<std::uint32_t> result;
    for (size_t i = 0; i < str.length(); i += 8) {
        result.push_back(std::stoul(str.substr(i, 8), nullptr, 16));
    }
    return result;
}

// Converts a hex string into a single uint32_t block count
std::uint32_t str_to_block(const std::string& block_count) {
    return std::stoul(block_count);
}

// Converts a hex string into a human-readable string
std::string hex_str_to_str(const std::string& str) {
    std::string result;
    for (size_t i = 0; i < str.length(); i += 2) {
        result += static_cast<char>(std::stoul(str.substr(i, 2), nullptr, 16));
    }
    return result;
}

// Converts a vector of uint8_t to a hex string
std::string vec_to_hex(const std::vector<std::uint8_t>& vec) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto c : vec) {
        oss << std::setw(2) << static_cast<int>(c);
    }
    return oss.str();
}

// Converts a string to a vector of uint8_t
std::vector<std::uint8_t> str_to_vec(const std::string& str) {
    return std::vector<std::uint8_t>(str.begin(), str.end());
}

} // namespace util

// Benchmark the encryption process
void benchmark_encryption(Chacha20& cipher, const std::vector<std::uint8_t>& msg_vec, int iterations) {
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        // Perform encryption but avoid unused variable warning
        std::vector<std::uint8_t> encrypted_msg = cipher.encrypt(msg_vec);
        (void)encrypted_msg;
    }
    auto end = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> elapsed = end - start;

    double total_ms = elapsed.count() * 1000.0;
    double per_run_ms = total_ms / iterations;

    std::cout << "Benchmark (" << iterations << " runs): "
              << total_ms << " ms total, "
              << per_run_ms << " ms per run\n";
}

// Runs a single test case
bool run_test_case(const std::string& key, const std::string& block_count, const std::string& nonce,
                   const std::string& message, const std::string& expected_result, int iterations) {
    std::array<std::uint32_t, 8> key_arr;
    std::copy_n(util::hex_str_to_vec(key).begin(), 8, key_arr.begin());

    std::array<std::uint32_t, 3> nonce_arr;
    std::copy_n(util::hex_str_to_vec(nonce).begin(), 3, nonce_arr.begin());

    std::uint32_t block_v = util::str_to_block(block_count);
    std::string msg = util::hex_str_to_str(message);
    std::vector<std::uint8_t> msg_vec = util::str_to_vec(msg);

    Chacha20 cipher(key_arr, block_v, nonce_arr);

    std::vector<std::uint8_t> encrypted = cipher.encrypt(msg_vec);
    std::string result_hex = util::vec_to_hex(encrypted);

    bool passed = (result_hex == expected_result);

    std::cout << "Test " << (passed ? "PASSED" : "FAILED") << "\n";
    if (!passed) {
        std::cout << "Expected: " << expected_result << "\n";
        std::cout << "Got     : " << result_hex << "\n";
    }

    // Only benchmark if the test passed
    if (passed) {
        benchmark_encryption(cipher, msg_vec, iterations);
    }

    std::cout << "---------------------------------------------\n";
    return passed;
}

#define ITERATIONS 100000

// Testcases are from https://datatracker.ietf.org/doc/html/rfc8439
int main() {
    std::cout << "Running test cases...\n";

    int passed = 0;
    int total = 0;

    total++; passed += run_test_case(
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", "1", "000000000000004a00000000",
        "4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e",
        "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d",
        ITERATIONS);

    total++; passed += run_test_case(
        "0000000000000000000000000000000000000000000000000000000000000000", "0", "000000000000000000000000",
        "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
        ITERATIONS);

    total++; passed += run_test_case(
        "0000000000000000000000000000000000000000000000000000000000000001", "1", "000000000000000000000002",
        "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f",
        "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221",
        ITERATIONS);

    total++; passed += run_test_case(
        "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0", "42", "000000000000000000000002",
        "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e",
        "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1",
        ITERATIONS);

    std::cout << passed << "/" << total << " test cases passed.\n";

    return (passed == total) ? 0 : 1;
}