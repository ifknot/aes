#include "catch2.h"

#include <vector>

#include "../crypto/nonce_factory.h"
#include "../util/phex.h"

TEST_CASE("Nonce Factory", "[.nonce_factory]") {
#ifndef NDEBUG

    #ifndef __RDSEED__

    SECTION("No HRNG :( PRSEED 32 nonce generate 12 byte nonce") {

        REQUIRE(crypto::can_rdseed() == false);
        crypto::nonce<> n;
        auto nonce_block = n();
        util::phex(nonce_block);
        std::vector<crypto::nonce<>::value_type> expect{0xef, 0xcd, 0xab, 0x89, 0xef, 0xcd, 0xab, 0x89, 0xef, 0xcd,
                                                        0xab, 0x89, 0x00, 0x00, 0x00, 0x00};
        for (size_t i{0}; i < 16u; ++i) {
            REQUIRE(nonce_block[i] == expect[i]);
        }
    }

    #else
    SECTION("Yes HRNG :) CSSEED 32 bit generate 12 byte nonce") {
        REQUIRE(crypto::can_rdseed() == true);
        crypto::nonce<> n;
        auto nonce_block = n();
        util::phex(nonce_block);
        std::vector<crypto::nonce<>::value_type> expect{0xef, 0xcd, 0xab, 0x89, 0xef, 0xcd, 0xab, 0x89, 0xef, 0xcd,
                                                        0xab, 0x89, 0x00, 0x00, 0x00, 0x00};
        for (size_t i{0}; i < 16u; ++i) {
            REQUIRE(nonce_block[i] == expect[i]);
        }
    }

    SECTION ("Yes HRNG :) CSSEED 16 bit generate 12 byte nonce") {
        REQUIRE(crypto::can_rdseed() == true);
        crypto::nonce<> n;
        auto nonce_block = n();
        util::phex(nonce_block);
        //ToDo: correct this down to 16 bits
        std::vector<crypto::nonce<>::value_type> expect{0xef, 0xcd, 0xab, 0x89, 0xef, 0xcd, 0xab, 0x89, 0xef, 0xcd,
                                                        0xab, 0x89, 0x00, 0x00, 0x00, 0x00};
        for (size_t i{0}; i < 16u; ++i) {
            REQUIRE(nonce_block[i] == expect[i]);
        }
    }

    #endif

#else

    SECTION("NDEBUG mode just print nonce values") {

        SECTION("Yes HRNG :) CSSEED 32 bit generate 12 byte nonce") {
            REQUIRE(crypto::can_rdseed() == true);
            crypto::nonce<> n;
            util::phex(n());
        }

        SECTION ("Yes HRNG :) CSSEED 16 bit generate 12 byte nonce") {
            REQUIRE(crypto::can_rdseed() == true);
            crypto::nonce<> n;
            util::phex(n());
        }

    }

#endif
}