#include "catch2.h"

#include "../crypto/aes_encrypt.h"
#include "../crypto/aes_decrypt.h"
#include "../util/phex.h"
#include "../util/stopwatch.h"

#include <iostream>

TEST_CASE("AES encrypt NIST tests", "[.aes_encrypt]") {

#ifdef NDEBUG
    static const size_t SAMPLES = 1'000'000;
#else
    static const size_t SAMPLES = 1'000;
#endif

    using block_t = crypto::aes::encrypt<>::block_t;
    using encode_t = crypto::aes::encrypt<>;
    using decode_t = crypto::aes::decrypt<>;
    using key_t = std::array<crypto::aes::encrypt<>::value_type, 32ul>;

    util::stopwatch<std::chrono::milliseconds> sw; //default nanoseconds

    block_t plain  = { 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a };

    SECTION("AES256 encrypt-decrypt NIST check") {

        key_t key = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                     0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

        block_t cipher = {0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1,
                          0x81, 0xf8};

        block_t test = plain;

        encode_t encrypt(key);
        decode_t decrypt(key);

        REQUIRE(encrypt.block_size() == crypto::BLOCK_SIZE);
        REQUIRE(decrypt.block_size() == crypto::BLOCK_SIZE);

        util::phex(test);
        util::phex(cipher);
        encrypt.block(test.begin());
        util::phex(test);

        REQUIRE(cipher == test);

        decrypt.block(test.begin());
        util::phex(plain);
        util::phex(test);
        REQUIRE(plain == test);

        sw.start();
        for(int i = 0; i < SAMPLES; ++i) {
            encrypt.block(test.begin());
        }
        sw.stop();
        std::cout << "\ntime encrypt " << SAMPLES << " blocks = " << sw.elapsed() / 1000.0 << "s" << std::endl;

        sw.start();
        for(int i = 0; i < SAMPLES; ++i) {
            decrypt.block(test.begin());
        }
        sw.stop();
        std::cout << "\ntime decrypt " << SAMPLES << " blocks = " << sw.elapsed() / 1000.0 << "s" << std::endl;

    }

    SECTION("AES192 encrypt-decrypt NIST check") {
        //Broken :(
    }

    SECTION("AES128 encrypt-decrypt NIST check") {
        //Broken :(
    }

}