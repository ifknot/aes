#include "catch2.h"

#include <array>
#include <vector>

#include <iostream>

#include "../crypto/block_cipher_factory.h"
#include "../util/stopwatch.h"

static const size_t SAMPLES = 1'000'000;
static const size_t TRIALS = 10;

TEST_CASE("Performance ifknot ECB ", "[ifknot performance]") {

    util::stopwatch<std::chrono::milliseconds> sw;

    SECTION("stopwatch ECB encrypt x 1,0000,000\n") {

        std::vector<uint8_t> plain = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };

        using cipher_t = crypto::block_cipher<crypto::ECB>;
        using key_t = std::array<cipher_t::value_type, 32>;

        key_t key = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                     0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

        std::vector<uint8_t> cipher = {0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8 };

        std::vector<uint8_t> test = plain;

        cipher_t AES256(key);

        REQUIRE(AES256.mode() == crypto::ECB);
        AES256.encrypt(test.begin(), test.end());
        REQUIRE(test == cipher);
        AES256.decrypt(test.begin(), test.end());
        REQUIRE(test == plain);

        for(size_t j{0}; j < TRIALS; ++j) {
            sw.start();
            for (size_t i = 0; i < SAMPLES; ++i) {
                AES256.encrypt(test.begin(), test.end());
            }
            sw.stop();
            std::cout << "\nT encrypt" << SAMPLES << " = " << sw.elapsed() / 1000.0 << std::endl;
        }
        for(size_t j{0}; j < TRIALS; ++j) {
            sw.start();
            for (size_t i = 0; i < SAMPLES; ++i) {
                AES256.decrypt(test.begin(), test.end());
            }
            sw.stop();
            std::cout << "\nT decrypt" << SAMPLES << " = " << sw.elapsed() / 1000.0 << std::endl;
        }

    }

}
