#include "catch2.h"

#include <vector>

#include "padder_factory.h"
#include "phex.h"

TEST_CASE("Padder Factory", "[padder_factory]") {

    SECTION("PKCS5") {
        using padder_t = crypto::padder<>;

        std::vector<padder_t::value_type> plain =
                {0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                 0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
                };

        padder_t pkcs5;

        std::vector<padder_t::value_type> padding(padder_t::block_size());

        for(size_t i{0}; i < 16; ++i) {
            size_t temp;
            plain.push_back(plain[i]);

                REQUIRE(pkcs5.mode() == crypto::PKCS5);
                util::phex(plain);
                temp = plain.size();
                size_t n = pkcs5.pad(plain.begin(), plain.end(), padding.begin());
                for(size_t j{0}; j < n; ++j) {
                    plain.push_back(padding[j]);
                }
                util::phex(plain);
                REQUIRE(plain.size() % pkcs5.block_size() == 0u);


                REQUIRE(pkcs5.mode() == crypto::PKCS5);
                util::phex(plain);
                plain.resize(plain.size() - pkcs5.unpad(plain.begin(), plain.end()));
                util::phex(plain);
                REQUIRE(plain.size() == temp);

        }

        for(size_t i{0}; i < 16; ++i) {
            size_t temp;
            plain.push_back(plain[i]);

                REQUIRE(pkcs5.mode() == crypto::PKCS5);
                util::phex(plain);
                temp = plain.size();
                size_t n = pkcs5.pad_value(plain.size());
                for(size_t j{0}; j < n; ++j) {
                    plain.push_back(static_cast<unsigned char &&>(n));
                }
                util::phex(plain);
                REQUIRE(plain.size() % pkcs5.block_size() == 0u);

                REQUIRE(pkcs5.mode() == crypto::PKCS5);
                util::phex(plain);
                plain.resize(plain.size() - pkcs5.unpad(plain.begin(), plain.end()));
                util::phex(plain);
                REQUIRE(plain.size() == temp);

        }

        for(size_t j{1}; j <= padder_t::block_size(); ++j) {

               REQUIRE(pkcs5.mode() == crypto::PKCS5);
                size_t n = pkcs5.pad_value(plain.size());
                for (size_t i{0}; i < n; ++i) {
                    plain.push_back(static_cast<unsigned char &&>(n));
                }
                auto it = plain.end() - j;
                (*it)--;
                util::phex(plain);
                CHECK_THROWS_AS(pkcs5.unpad(plain.begin(), plain.end()), doh::cipher_exception);
                (*it)++;
                plain.resize(plain.size() - pkcs5.unpad(plain.begin(), plain.end()));

        }

    }

}