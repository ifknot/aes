#include "catch2.h"

#include <array>
#include <vector>

#ifdef NDEBUG
#include <iostream>
#endif

#include "block_cipher_factory.h"
#include "stopwatch.h"
#include "phex.h"

static const size_t SAMPLES = 1'000;

TEST_CASE("AES block cipher modes", "[block_cipher_factory]") {

    using aes_t = crypto::block_cipher<>;
    using block_t = aes_t::block_t;

    util::stopwatch<> sw;

    SECTION("test ECB should encrypt & decrypt multiple blocks correctly\n") {

        std::vector<uint8_t> plain = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                                      0x93, 0x17, 0x2a,
                                      0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                                      0x93, 0x17, 0x2a,
                                      0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                                      0x93, 0x17, 0x2a,
                                      0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                                      0x93, 0x17, 0x2a};

        using cipher_t = crypto::block_cipher<>;
        using key_t = std::array<aes_t::value_type, 32>;

        key_t key = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                     0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

        std::vector<uint8_t> cipher = {0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d,
                                       0xb1, 0x81, 0xf8,
                                       0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d,
                                       0xb1, 0x81, 0xf8,
                                       0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d,
                                       0xb1, 0x81, 0xf8,
                                       0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 0x06, 0x4b, 0x5a, 0x7e, 0x3d,
                                       0xb1, 0x81, 0xf8};

        std::vector<uint8_t> test = plain;

        cipher_t aes(key);

        REQUIRE(aes.mode() == crypto::ECB);

        util::phex(test);
        util::phex(cipher);
        aes.encrypt(test.begin(), test.end());
        util::phex(test);

        REQUIRE(test == cipher);

        aes.decrypt(test.begin(), test.end());
        util::phex(plain);
        util::phex(test);
        REQUIRE(test == plain);
sw.start();
                        for(size_t i = 0; i < SAMPLES; ++i) {
                            aes.encrypt(test.begin(), test.end());
                        }
                        sw.stop();
                        std::cout << "\nT encrypt = " << sw.elapsed() << std::endl;

                        sw.start();
                        for(size_t i = 0; i < SAMPLES; ++i) {
                            aes.decrypt(test.begin(), test.end());
                        }
                        sw.stop();
                        std::cout << "\nT decrypt = " << sw.elapsed() << std::endl;
#if defined(NDEBUG) // provide performance tests
        sw.start();
                        for(size_t i = 0; i < SAMPLES; ++i) {
                            aes.encrypt(test.begin(), test.end());
                        }
                        sw.stop();
                        std::cout << "\nT encrypt = " << sw.elapsed() << std::endl;

                        sw.start();
                        for(size_t i = 0; i < SAMPLES; ++i) {
                            aes.decrypt(test.begin(), test.end());
                        }
                        sw.stop();
                        std::cout << "\nT decrypt = " << sw.elapsed() << std::endl;
#endif

    }

    SECTION("test CBC should encrypt and decrypt multiple blocks correctly\n") {

        std::vector<uint8_t> plain = {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                                      0x93, 0x17, 0x2a,
                                      0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45,
                                      0xaf, 0x8e, 0x51,
                                      0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a,
                                      0x0a, 0x52, 0xef,
                                      0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6,
                                      0x6c, 0x37, 0x10};

        using cipher_t = crypto::block_cipher<crypto::CBC>;
        using key_t = std::array<aes_t::value_type, 32>;

        key_t key = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                     0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

        block_t iv = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

        std::vector<uint8_t> cipher = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
                                       0x0d, 0x0e, 0x0f,
                                       0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 0x77, 0x9e, 0xab, 0xfb, 0x5f,
                                       0x7b, 0xfb, 0xd6,
                                       0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 0x67, 0x9f, 0x77, 0x7b, 0xc6,
                                       0x70, 0x2c, 0x7d,
                                       0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 0xa5, 0x30, 0xe2, 0x63, 0x04,
                                       0x23, 0x14, 0x61,
                                       0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 0xda, 0x6c, 0x19, 0x07, 0x8c,
                                       0x6a, 0x9d, 0x1b};

        std::vector<uint8_t> test = plain;

        cipher_t aes(key);

        REQUIRE(aes.mode() == crypto::CBC);
        util::phex(test);
        //put the initialization vector at the front
        test.insert(test.begin(), iv.begin(), iv.end());
        util::phex(test);
        util::phex(cipher);
        aes.encrypt(test.begin() + 16, test.end());
        util::phex(test);
        REQUIRE(test == cipher);


        util::phex(test);
        aes.decrypt(test.begin() + 16, test.end());
        util::phex(test);
        //strip the iv from the front using the copy-swap idiom
        std::vector<uint8_t>{test.begin() + 16, test.end()}.swap(test);
        util::phex(test);
        util::phex(plain);
        REQUIRE(test == plain);

#if defined(NDEBUG)
        test.insert(test.begin(), iv.begin(), iv.end());
        sw.start();
        for(size_t i = 0; i < SAMPLES; ++i) {
            aes.encrypt(test.begin(), test.end());
        }
        sw.stop();
        std::cout << "\nT encrypt = " << sw.elapsed() << std::endl;

        sw.start();
        for(size_t i = 0; i < SAMPLES; ++i) {
            aes.decrypt(test.begin(), test.end());
        }
        sw.stop();
        std::cout << "\nT decrypt = " << sw.elapsed() << std::endl;
#endif
    }

#if defined(NDEBUG)
    SECTION("test CTR should increment counter block correctly\n") {

        std::vector<uint8_t> plain = {  0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
                                        0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
                                        0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
                                        0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6 };

        using cipher_t = crypto::block_cipher<crypto::CTR>;
        std::vector<uint8_t> nonce = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
        std::vector<uint8_t> nonce65536 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00 };
        sw.start();
        for(size_t j{0}; j <256; ++j) {
            for (size_t i{0}; i < 256; ++i) {
                cipher_t::inc_block(nonce);
            }
        }
        util::phex(nonce);
        sw.stop();
        std::cout << "\nT inc 65536 = " << sw.elapsed() << std::endl;
        AssertThat(nonce == nonce65536, IsTrue());
    }
#endif

    SECTION("should encrypt and decrypt multiple blocks correctly\n") {
        using cipher_t = crypto::block_cipher<crypto::CTR>;
        using key_t = std::array<aes_t::value_type, 32>;

        std::vector<uint8_t> plain = { 0x60, 0x1e, 0xc3, 0x13, 0x77, 0x57, 0x89, 0xa5, 0xb7, 0xa7, 0xf5, 0x04, 0xbb, 0xf3, 0xd2, 0x28,
                                       0xf4, 0x43, 0xe3, 0xca, 0x4d, 0x62, 0xb5, 0x9a, 0xca, 0x84, 0xe9, 0x90, 0xca, 0xca, 0xf5, 0xc5,
                                       0x2b, 0x09, 0x30, 0xda, 0xa2, 0x3d, 0xe9, 0x4c, 0xe8, 0x70, 0x17, 0xba, 0x2d, 0x84, 0x98, 0x8d,
                                       0xdf, 0xc9, 0xc5, 0x8d, 0xb6, 0x7a, 0xad, 0xa6, 0x13, 0xc2, 0xdd, 0x08, 0x45, 0x79, 0x41, 0xa6 };

        key_t key = {0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                     0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4};

        block_t nonce = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe,
                         0xff};

        std::vector<uint8_t> cipher = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9, 0xfa, 0xfb, 0xfc,
                                       0xfd, 0xfe, 0xff,
                                       0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73,
                                       0x93, 0x17, 0x2a,
                                       0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45,
                                       0xaf, 0x8e, 0x51,
                                       0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a,
                                       0x0a, 0x52, 0xef,
                                       0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6,
                                       0x6c, 0x37, 0x10};

        std::vector<uint8_t> test = plain;

        cipher_t aes(key);

        REQUIRE(aes.mode() == crypto::CTR);
        util::phex(test);
        //put the nonce (64 bit) + counter (64 bit) at the front
        test.insert(test.begin(), nonce.begin(), nonce.end());
        util::phex(test);
        util::phex(cipher);
        aes.encrypt(test.begin() + 16, test.end());
        util::phex(test);
        REQUIRE(test == cipher);

        util::phex(test);
        aes.decrypt(test.begin() + 16, test.end());
        util::phex(test);
        //strip the iv from the front using the copy-swap idiom
        std::vector<uint8_t>{test.begin() + 16, test.end()}.swap(test);
        util::phex(test);
        util::phex(plain);
        REQUIRE(test == plain);
#if defined(NDEBUG)
        test.insert(test.begin(), nc.begin(), nc.end());
        sw.start();
        for(size_t i = 0; i < SAMPLES; ++i) {
            aes.encrypt(test.begin(), test.end());
        }
        sw.stop();
        std::cout << "\nT encrypt = " << sw.elapsed() << std::endl;

        sw.start();
        for(size_t i = 0; i < SAMPLES; ++i) {
            aes.decrypt(test.begin(), test.end());
        }
        sw.stop();
        std::cout << "\nT decrypt = " << sw.elapsed() << std::endl;
#endif
    }

}