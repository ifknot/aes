#ifndef AES_CPP17_AES_H
#define AES_CPP17_AES_H

#include <cstdint>
#include <stddef.h>

namespace pug::crypto::aes {

    /**
     * R as the round number - round keys needed:
     * + 11 round keys for AES-128
     * + 13 keys for AES-192
     * + 15 keys for AES-256
     */
    enum ROUNDS : size_t {
        R128 = 11, R192 = 13, R256 = 15
    };

    /**
     * N as the length of the key in 32-bit words:
     * + 4 words AES-128
     * + 6 words AES-192
     * + 8 words AES-256
     */
    enum KEY_LENGTH : size_t {
        N128 = 4, N192 = 6, N256 = 8
    };

    /**
     * multiply by 2 in the Rijndael algo's Galois' Field (GF)
     * @param x
     * @return
     */
    static inline uint_fast32_t GF2(uint_fast32_t x) {
        return (x << 1u)           //implicitly removes high bit because 8-bit, (so * 0x1b and not 0x11b)
               ^                  //xor
               (((x >> 7u) & 1u)    // arithmetic right shift, thus shifting in either zeros or ones
                * 0x1bu);          // Rijndael's Galois field
    }

    /**
     * TODO table lookup of values for x×9, x×11, x×13 and x×14 https://en.wikipedia.org/wiki/Rijndael_MixColumns
     * @brief Inverse multiplication in a finite field for the inverse mix column directions.
     * A series of GF(2^8) multiplications however, instead of multiplying by 1, 2 and 3, as for encrypt multiplying
     * by 9, 11, 13 and 14.
     * Mix column matrix _M_, it is true that M^4 = I, therefore performing this transformation thrice...
     * results in its inverse (M^3=M^−1).
     * So the multiplication rule is a little more complex than the x 2 rule @see GF2 but can be intuitively achieved
     * by taking the x×2 function and using it three times over: (GF '+' is XOR)
     * x×9=(((x×2)×2)×2)+x
     * x×11=((((x×2)×2)+x)×2)+x
     * x×13=((((x×2)+x)×2)×2)+x
     * x×14=((((x×2)+x)×2)+x)×2
     * @note it is slower than using a lookup table
     * @param x
     * @param y
     * @return
     */
    static inline uint_fast32_t GFmul(uint_fast32_t x, uint_fast32_t y) {
        return ((y & 1u) * x) ^
               ((y >> 1u & 1u) * GF2(x)) ^
               ((y >> 2u & 1u) * GF2(GF2(x))) ^
               (y >> 3u & 1u) * GF2(GF2(GF2(x))) ^
               ((y >> 4u & 1u) * GF2(GF2(GF2(GF2(x)))));
    }

}

#endif //AES_CPP17_AES_H
