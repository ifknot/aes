#ifndef AES_CPP17_PADDER_FACTORY_H
#define AES_CPP17_PADDER_FACTORY_H

#include <vector>
#include <cstdint>

#include <iostream>

#include "cipher_exception.h"

namespace crypto {

    enum padder_mode_t {
        PKCS5 //ToDo: , PKCS7, ANSIX923, ONESZEROS
    };

    /**
     * @brief General purpose iterator based padding schemes for ECB & CBC block ciphers
     * To perform encryption with a block cipher then the length of the input to be encrypted _must_ be an exact
     * multiple of the block length in bytes.
     * @note It is up to the sender and receiver of encrypted data to agree on the convention used.
     * @tparam M
     * @tparam BLOCK_SIZE
     * @tparam T
     */
    template<padder_mode_t M = PKCS5, size_t BLOCK_SIZE = 16, typename T = uint8_t>
    struct padder {

        //ToDo: static_assert BLOCK_SIZE multiple of 8 and less than 2040

        using value_type  = T;

        /**
         * @brief general purpose padding interface for writing pad values to an external container
         * If the block length is _B_then add _N_padding bytes of value _N_ to make the input length up to the
         * next exact multiple of B.
         * @note If the input length is already an exact multiple of B then add B bytes of value B.
         * Thus padding of length N between one and B bytes is always added in an unambiguous manner.
         * @tparam Iterator
         * @param first
         * @param last
         * @param out - iterator to a destination container with _at least_ block length space
         * @return size_t the number of padding bytes written
         */
        template<typename ConstIterator, typename Iterator>
        size_t pad(ConstIterator first, ConstIterator last, Iterator out) {
            size_t pv= pad_value(static_cast<size_t>(std::distance(first, last)));
            for(auto i{pv}; i--;) {
                *out++ = pv;
            }
            return pv;
        }

        /**
         * @brief short cut unique to the repeated values of PKCS5
         * @param data_size
         * @return pad value - which can be used in a simple loop to pad the data container
         */
        inline size_t pad_value(size_t data_size) {
            return block_size() - data_size % block_size();
        }

        /**
         * @brief After decrypting, check that the last N bytes of the decrypted data all have value N with 1 < N ≤ B.
         * If so return nuber of bytes to strip, otherwise throw a decryption error.
         * @tparam Iterator
         * @param first
         * @param last
         * @return size_t the number of padding bytes to be stripped
         */
        template<typename ConstIterator>
        size_t unpad(ConstIterator first, ConstIterator last) {
            for(auto i{*(last - 1)}; i;) {
                if(*(last - i--) != *(last - 1)) {
                    throw doh::cipher_exception(doh::UNPADDING);
                }
            }
            return *(last - 1);
        }

        inline static padder_mode_t mode() {
            return M;
        }

        inline static size_t block_size() {
            return BLOCK_SIZE;
        }

    };

}


#endif //AES_CPP17_PADDER_FACTORY_H
