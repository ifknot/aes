#include "catch2.h"

#include "phex.h"
#include "stopwatch.h"
#include "aes_encrypt.h"

#include <iostream>

TEST_CASE( "AES encrypt NIST tests", "[aes_encrypt]" ) {

    using block_t = crypto::aes::encrypt<>::block_t;

    util::stopwatch<> sw; //default is nanoseconds
    block_t block{};

    SECTION("AES256 encrypt NIST examples") {
        util::phex(block);
        REQUIRE(block.size() == crypto::BLOCK_SIZE);
    }

    SECTION("AES256 encrypt million performance") {
        sw.start();

        sw.stop();
        std::cout << "t=" << sw.elapsed() << "ns\n";
    }

}