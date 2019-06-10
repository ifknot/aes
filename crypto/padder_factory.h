#ifndef AES_CPP17_PADDER_FACTORY_H
#define AES_CPP17_PADDER_FACTORY_H

#include <vector>
#include <cstdint>

//#include <iostream>

#include "cipher_exception.h"

namespace crypto {

    /**
     * The difference between the PKCS#5 and PKCS#7 padding mechanisms is the block size:
     * + PKCS#5 padding is defined for 8-byte block sizes
     * + PKCS#7 padding will work for any block size from 1 to 255 bytes
     * So, fundamentally, PKCS#5 padding is a subset of PKCS#7 padding for 8 byte block sizes.
     * Therefore, PKCS#5 padding can not be used for 16 byte block size AES.
     * @note PKCS#5 padding was only defined with (triple) DES operation in mind.
     */
    enum padder_mode_t {
        PKCS7, PKCS5, ANSIX923 //ToDo: ISO10126
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
    template<padder_mode_t M = PKCS7, size_t BLOCK_SIZE = 16, typename T = uint8_t>
    struct padder {

        //ToDo: static_assert BLOCK_SIZE multiple of 8 and less than 2040

        using value_type  = T;

        /**
         * @brief PKCS7 padding scheme for writing pad values to an external container
         * If the block length is _B_then add _N_ padding bytes of value _N_ to make the input length up to the
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
         * If so return number of bytes to strip, otherwise throw a decryption error.
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

    template<size_t BLOCK_SIZE,typename T>
    struct padder<ANSIX923, BLOCK_SIZE, T> {

        //ToDo: static_assert BLOCK_SIZE multiple of 8 and less than 2040

        using value_type  = T;

        /**
         * @brief ANSO X 9.23 padding scheme for writing pad values to an external container
         * ANSI X9.23, between 1 and 8 bytes are always added as padding.
         * The block is padded with random bytes (although many implementations use 00) and the last byte of the block
         * is set to the number of bytes added.
         * @tparam Iterator
         * @param first
         * @param last
         * @param out - iterator to a destination container with _at least_ block length space
         * @return size_t the number of padding bytes written
         */
        template<typename ConstIterator, typename Iterator>
        size_t pad(ConstIterator first, ConstIterator last, Iterator out) {
            size_t tv= terminator(static_cast<size_t>(std::distance(first, last)));
            for(auto i{tv - 1}; i--;) {
                *out++ = 0x00;
            }
            *out = tv;
            return tv;
        }

        /**
         * @brief After decrypting, check that the last N -1  bytes of the decrypted data all have value 0x00 with 1 < N ≤ B.
         * If so return number of bytes to strip, otherwise throw a decryption error.
         * @tparam Iterator
         * @param first
         * @param last
         * @return size_t the number of padding bytes to be stripped
         */
        template<typename ConstIterator>
        size_t unpad(ConstIterator first, ConstIterator last) {
            int i{*(last - 1)};
            for(int i{*(last - 1)}; i > 1; i--) {
                if(*(last - i) != 0x00) {
                    throw doh::cipher_exception(doh::UNPADDING);
                }
            }
            return *(last - 1);
        }

        inline static padder_mode_t mode() {
            return ANSIX923;
        }

        inline static size_t block_size() {
            return BLOCK_SIZE;
        }

    private:

        /**
         * @brief terminator value
         * @param data_size
         * @return pad value - which can be used in a simple loop to pad the data container
         */
        inline size_t terminator(size_t data_size) {
            return block_size() - data_size % block_size();
        }

    };

    /**
     * PKCS#5 padding is defined for 8-byte block sizes
     * @warning PKCS#5 padding can not be used for 16 byte block size AES.
     * @note PKCS#5 padding was only defined with (triple) DES operation in mind.
     * @tparam T
     */
    template<typename T>
    struct padder<PKCS5, 8, T> {

        //ToDo: static_assert BLOCK_SIZE multiple of 8 and less than 2040

        using value_type  = T;

        /**
         * @brief PKCS7 padding scheme for writing pad values to an external container
         * If the block length is _B_then add _N_ padding bytes of value _N_ to make the input length up to the
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
         * If so return number of bytes to strip, otherwise throw a decryption error.
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
            return PKCS5;
        }

        inline static size_t block_size() {
            return 8;
        }

    };


}


#endif //AES_CPP17_PADDER_FACTORY_H
